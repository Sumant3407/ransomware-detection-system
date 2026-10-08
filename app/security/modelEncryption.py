"""Model artifact encryption, integrity verification, and secure loading."""

import hashlib
import hmac
import io
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional, Union

import joblib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# Magic byte header identifying encrypted model files (v1)
ENCRYPTED_MAGIC_HEADER = b"RDME\x01"  # Ransomware Detection Model Encrypted v1


class ModelEncryptionError(ValueError):
    """Raised when model encryption, decryption, or integrity verification fails."""


class ModelTamperError(ModelEncryptionError):
    """Raised when a model file has been modified or corrupted."""


class ModelEncryption:
    """
    Encrypts, decrypts, and verifies ML model artifacts using AES-256-GCM.

    File format:
    - Magic Header (5 bytes): RDME\x01
    - Salt (16 bytes)
    - Nonce (12 bytes)
    - Ciphertext (variable length)
    - Authentication Tag (16 bytes)
    - Payload HMAC-SHA256 (32 bytes)
    """

    ALGORITHM_VERSION = 1
    CIPHER_ALGORITHM = "AES-256-GCM"
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    TAG_SIZE = 16  # 128 bits
    SALT_SIZE = 16  # 128 bits
    HMAC_SIZE = 32  # 256 bits SHA-256
    ITERATIONS = 480000  # NIST recommended (2024)

    def __init__(self, systemIdentifier: Optional[str] = None):
        """
        Initialize model encryption with system-specific key derivation.

        Args:
            systemIdentifier: System ID for key derivation. If None, uses environment variable
                              RANSOMWARE_ENCRYPTION_KEY or system MAC address.
        """
        if systemIdentifier is None:
            envKey = os.environ.get("RANSOMWARE_ENCRYPTION_KEY")
            if envKey:
                systemIdentifier = envKey
            else:
                try:
                    systemIdentifier = str(uuid.getnode())
                except Exception as error:
                    logger.debug(f"Unable to read machine node ID, using fallback: {error}")
                    systemIdentifier = "default-ransomware-detector-system-key"

        self.systemIdentifier = systemIdentifier
        logger.debug(f"ModelEncryption initialized with system ID: {self.systemIdentifier[:8]}...")

    def _deriveKeys(self, salt: bytes) -> tuple[bytes, bytes]:
        """
        Derive both encryption key (AES-256) and HMAC key (SHA-256) from system identifier.

        Args:
            salt: Random 16-byte salt

        Returns:
            Tuple of (encryptionKey: 32 bytes, hmacKey: 32 bytes)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE * 2,  # 64 bytes (32 for AES, 32 for HMAC)
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend(),
        )
        derived = kdf.derive(self.systemIdentifier.encode("utf-8"))
        encryptionKey = derived[: self.KEY_SIZE]
        hmacKey = derived[self.KEY_SIZE :]
        return encryptionKey, hmacKey

    @staticmethod
    def isEncryptedBytes(data: bytes) -> bool:
        """Check if raw bytes have the encrypted model magic header."""
        return data.startswith(ENCRYPTED_MAGIC_HEADER)

    @classmethod
    def isEncryptedFile(cls, filePath: Path) -> bool:
        """Check if a file on disk is an encrypted model artifact."""
        filePath = Path(filePath)
        if not filePath.is_file():
            return False
        try:
            with open(filePath, "rb") as f:
                header = f.read(len(ENCRYPTED_MAGIC_HEADER))
                return header == ENCRYPTED_MAGIC_HEADER
        except OSError:
            return False

    def encryptBytes(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext bytes using AES-256-GCM and append HMAC-SHA256.

        Args:
            plaintext: Plaintext bytes to encrypt

        Returns:
            Encrypted byte payload
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise ModelEncryptionError("Plaintext must be bytes or bytearray")

        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        encryptionKey, hmacKey = self._deriveKeys(salt)

        # Encrypt with AES-256-GCM
        cipher = Cipher(
            algorithms.AES(encryptionKey),
            modes.GCM(nonce),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        # Header + Salt + Nonce + Ciphertext + Tag
        encryptedBody = ENCRYPTED_MAGIC_HEADER + salt + nonce + ciphertext + tag

        # Compute HMAC over entire encrypted body for external integrity check
        h = hmac.new(hmacKey, encryptedBody, hashlib.sha256)
        payloadHmac = h.digest()

        return encryptedBody + payloadHmac

    def decryptBytes(self, encryptedData: bytes) -> bytes:
        """
        Verify integrity and decrypt AES-256-GCM encrypted payload.

        Args:
            encryptedData: Encrypted byte payload

        Returns:
            Decrypted plaintext bytes

        Raises:
            ModelTamperError: If authentication tag or HMAC verification fails
            ModelEncryptionError: If format or decryption fails
        """
        minSize = (
            len(ENCRYPTED_MAGIC_HEADER)
            + self.SALT_SIZE
            + self.NONCE_SIZE
            + self.TAG_SIZE
            + self.HMAC_SIZE
        )
        if len(encryptedData) < minSize:
            raise ModelEncryptionError("Encrypted payload is malformed or truncated")

        if not encryptedData.startswith(ENCRYPTED_MAGIC_HEADER):
            raise ModelEncryptionError("Invalid magic header: not an encrypted model artifact")

        offset = len(ENCRYPTED_MAGIC_HEADER)
        salt = encryptedData[offset : offset + self.SALT_SIZE]
        offset += self.SALT_SIZE

        nonce = encryptedData[offset : offset + self.NONCE_SIZE]
        offset += self.NONCE_SIZE

        # The trailing 32 bytes are the HMAC
        encryptedBody = encryptedData[:-self.HMAC_SIZE]
        expectedHmac = encryptedData[-self.HMAC_SIZE :]

        # Derive keys
        encryptionKey, hmacKey = self._deriveKeys(salt)

        # 1. Verify external HMAC
        h = hmac.new(hmacKey, encryptedBody, hashlib.sha256)
        computedHmac = h.digest()
        if not hmac.compare_digest(computedHmac, expectedHmac):
            logger.error("Model HMAC integrity check failed - possible tampering detected")
            raise ModelTamperError("Model artifact HMAC verification failed (tampered or corrupted)")

        # 2. Extract ciphertext and GCM tag
        tag = encryptedBody[-self.TAG_SIZE :]
        ciphertext = encryptedBody[offset : -self.TAG_SIZE]

        # 3. Decrypt and verify GCM tag
        try:
            cipher = Cipher(
                algorithms.AES(encryptionKey),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as error:
            logger.error(f"AES-GCM decryption failed: {error}")
            raise ModelTamperError(f"Model decryption authentication failed: {error}") from error

    def encryptFile(self, modelPath: Path, outputPath: Optional[Path] = None) -> Path:
        """
        Encrypt a model file on disk.

        Args:
            modelPath: Path to model file to encrypt
            outputPath: Target output path (if None, overwrites modelPath atomically)

        Returns:
            Path to encrypted model file
        """
        modelPath = Path(modelPath).resolve()
        if not modelPath.is_file():
            raise ModelEncryptionError(f"Model file not found: {modelPath}")

        targetPath = Path(outputPath).resolve() if outputPath else modelPath
        plaintext = modelPath.read_bytes()

        # If already encrypted, avoid double encryption
        if self.isEncryptedBytes(plaintext):
            logger.info(f"Model is already encrypted: {modelPath}")
            return targetPath

        encrypted = self.encryptBytes(plaintext)

        # Atomic write
        tempFile = targetPath.with_suffix(".tmp_enc")
        tempFile.write_bytes(encrypted)
        tempFile.replace(targetPath)

        logger.info(
            f"Model encrypted successfully: {targetPath} ({len(encrypted)} bytes)",
            extra={"event": "model_encryption", "context": {"path": str(targetPath), "size": len(encrypted)}},
        )
        return targetPath

    def decryptFile(self, modelPath: Path, outputPath: Optional[Path] = None) -> Path:
        """
        Decrypt a model file on disk to a target path.

        Args:
            modelPath: Path to encrypted model file
            outputPath: Target output path

        Returns:
            Path to decrypted model file
        """
        modelPath = Path(modelPath).resolve()
        if not modelPath.is_file():
            raise ModelEncryptionError(f"Model file not found: {modelPath}")

        if outputPath is None:
            raise ModelEncryptionError("outputPath is required for decryptFile")

        targetPath = Path(outputPath).resolve()
        encryptedData = modelPath.read_bytes()
        plaintext = self.decryptBytes(encryptedData)

        tempFile = targetPath.with_suffix(".tmp_dec")
        tempFile.write_bytes(plaintext)
        tempFile.replace(targetPath)

        logger.info(
            f"Model decrypted successfully: {targetPath}",
            extra={"event": "model_decryption", "context": {"path": str(targetPath)}},
        )
        return targetPath

    def loadModel(self, modelPath: Path) -> Any:
        """
        Load a model artifact (transparently decrypting if encrypted).

        Args:
            modelPath: Path to model file

        Returns:
            Deserialized Python model object / dictionary
        """
        modelPath = Path(modelPath).resolve()
        if not modelPath.is_file():
            raise ModelEncryptionError(f"Model file not found: {modelPath}")

        data = modelPath.read_bytes()
        if self.isEncryptedBytes(data):
            logger.info(f"Loading AES-256-GCM encrypted model: {modelPath.name}")
            plaintext = self.decryptBytes(data)
            buffer = io.BytesIO(plaintext)
            return joblib.load(buffer)
        else:
            logger.debug(f"Loading unencrypted model: {modelPath.name}")
            return joblib.load(modelPath)

    def computeChecksum(self, data: bytes) -> str:
        """Compute SHA-256 checksum of data."""
        return hashlib.sha256(data).hexdigest()

    def verifyChecksum(self, data: bytes, expectedChecksum: str) -> bool:
        """Verify data against expected SHA-256 checksum."""
        computed = self.computeChecksum(data)
        return hmac.compare_digest(computed, expectedChecksum)
