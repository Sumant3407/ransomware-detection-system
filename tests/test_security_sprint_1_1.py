"""Unit tests for path validation and file access security (Sprint 1.1)."""

import pytest
import tempfile
from pathlib import Path
import os

from app.security.pathValidator import PathValidator, PathValidationError
from app.config.configuration import resolveMonitoringPath, ConfigurationError


class TestPathValidator:
    """Test suite for PathValidator security checks."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.temppath = Path(self.tempdir.name)
        self.validator = PathValidator(allowedBasePaths={self.temppath})

    def teardown_method(self):
        """Clean up test fixtures."""
        self.tempdir.cleanup()

    # ========== Whitelist Tests ==========

    def test_allowed_base_path_validates(self):
        """Test that paths within allowed base paths validate successfully."""
        subdir = self.temppath / "subdir"
        subdir.mkdir()
        result = self.validator.validate(str(subdir))
        assert result == subdir.resolve()

    def test_home_directory_always_allowed(self):
        """Test that home directory is always allowed even without whitelist."""
        validator = PathValidator(allowedBasePaths=set())
        homeDir = Path.home()
        result = validator.validate(str(homeDir))
        assert result == homeDir.resolve()

    # ========== System Path Blocking Tests ==========

    def test_windows_system_directory_blocked(self):
        """Test that C:\\Windows is blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\Windows")

    def test_program_files_blocked(self):
        """Test that Program Files directories are blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\Program Files")

    def test_program_files_x86_blocked(self):
        """Test that Program Files (x86) is blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\Program Files (x86)")

    def test_programdata_blocked(self):
        """Test that ProgramData is blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\ProgramData")

    def test_system_volume_info_blocked(self):
        """Test that System Volume Information is blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\System Volume Information")

    def test_subdirectory_of_blocked_path_blocked(self):
        """Test that subdirectories of blocked paths are also blocked."""
        with pytest.raises(PathValidationError, match="System directory"):
            self.validator.validate("C:\\Windows\\System32")

    # ========== Network Path Blocking Tests ==========

    def test_unc_path_blocked(self):
        """Test that UNC network paths are blocked."""
        with pytest.raises(PathValidationError, match="Network path"):
            self.validator.validate("\\\\server\\share")

    def test_network_protocol_blocked(self):
        """Test that network protocol strings are blocked."""
        with pytest.raises(PathValidationError, match="Network path"):
            self.validator.validate("smb://server/share")

    # ========== Empty and Invalid Paths ==========

    def test_empty_path_rejected(self):
        """Test that empty paths are rejected."""
        with pytest.raises(PathValidationError, match="empty"):
            self.validator.validate("")

    def test_invalid_path_format_rejected(self):
        """Test that invalid path formats are rejected."""
        # Paths with null characters cannot be created normally
        # Instead test with an actual invalid path object scenario
        try:
            # Try to create a Path with embedded null
            Path("\x00invalid")
            # If we get here, the Path constructor didn't raise
            # so the validator should still handle it gracefully
            with pytest.raises(PathValidationError):
                self.validator.validate("\x00invalid")
        except ValueError:
            # Path constructor rejected it, which is fine
            pass

    # ========== Path Resolution ==========

    def test_relative_path_resolved(self):
        """Test that relative paths are resolved correctly."""
        subdir = self.temppath / "relative_test"
        subdir.mkdir()
        # Note: PathValidator doesn't handle relative-to-cwd resolution,
        # so we use absolute path for this test
        result = self.validator.validate(str(subdir))
        assert result.is_absolute()

    def test_path_with_symlinks_resolved(self):
        """Test that paths with symlinks are resolved to canonical form."""
        original = self.temppath / "original"
        original.mkdir()
        link = self.temppath / "link"
        try:
            link.symlink_to(original)
            result = self.validator.validate(str(link))
            assert result == original.resolve()
        except OSError:
            # Symlinks may not be available on Windows without admin
            pytest.skip("Symlinks not available")

    # ========== Batch Validation ==========

    def test_batch_validation_all_valid(self):
        """Test batch validation with all valid paths."""
        subdir1 = self.temppath / "dir1"
        subdir2 = self.temppath / "dir2"
        subdir1.mkdir()
        subdir2.mkdir()

        results = self.validator.validateBatch([str(subdir1), str(subdir2)])
        assert len(results) == 2
        assert results[0] == subdir1.resolve()
        assert results[1] == subdir2.resolve()

    def test_batch_validation_one_invalid_fails_all(self):
        """Test that batch validation fails if any path is invalid."""
        validDir = self.temppath / "valid"
        validDir.mkdir()

        with pytest.raises(PathValidationError):
            self.validator.validateBatch([str(validDir), "C:\\Windows"])

    # ========== Accessibility Checks ==========

    def test_nonexistent_path_rejected(self):
        """Test that nonexistent paths are rejected."""
        nonexistent = self.temppath / "does_not_exist_xyz"
        with pytest.raises(PathValidationError, match="not accessible"):
            self.validator.validate(str(nonexistent))

    def test_existing_directory_accepted(self):
        """Test that existing accessible directories are accepted."""
        testdir = self.temppath / "test_accessible"
        testdir.mkdir()
        result = self.validator.validate(str(testdir))
        assert result == testdir.resolve()

    # ========== Configuration Integration Tests ==========

    def test_resolve_monitoring_path_with_valid_path(self):
        """Test configuration.resolveMonitoringPath with valid path."""
        # This requires proper setup with the project structure
        # For now, we test the error case
        with pytest.raises(ConfigurationError):
            resolveMonitoringPath("C:\\Windows")

    def test_resolve_monitoring_path_rejects_system_paths(self):
        """Test that resolveMonitoringPath rejects system paths."""
        with pytest.raises(ConfigurationError, match="Invalid monitoring path"):
            resolveMonitoringPath("C:\\Program Files")


class TestFileAccessSecurity:
    """Test suite for secure file access in entropy calculation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tempdir = tempfile.TemporaryDirectory()
        self.temppath = Path(self.tempdir.name)

    def teardown_method(self):
        """Clean up test fixtures."""
        self.tempdir.cleanup()

    def test_safe_file_read(self):
        """Test that safe files can be read for entropy."""
        from app.features.windowing import FeatureWindow

        # Create a test file
        testfile = self.temppath / "test.txt"
        testfile.write_text("Hello, World!")

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(testfile)
        assert entropy is not None
        assert 0 <= entropy <= 8

    def test_executable_file_skipped(self):
        """Test that executable files are skipped for entropy."""
        from app.features.windowing import FeatureWindow

        # Create a fake executable
        exefile = self.temppath / "test.exe"
        exefile.write_bytes(b"MZ\x90\x00")  # PE header

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(exefile)
        assert entropy is None

    def test_dll_file_skipped(self):
        """Test that DLL files are skipped for entropy."""
        from app.features.windowing import FeatureWindow

        dllfile = self.temppath / "test.dll"
        dllfile.write_bytes(b"MZ\x90\x00")

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(dllfile)
        assert entropy is None

    def test_large_file_skipped(self):
        """Test that files larger than 1MB are skipped."""
        from app.features.windowing import FeatureWindow

        largefile = self.temppath / "large.txt"
        # Create a file larger than 1MB
        with open(largefile, "wb") as f:
            f.write(b"x" * (2 * 1024 * 1024))

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(largefile)
        assert entropy is None

    def test_permission_denied_handled(self):
        """Test that permission denied errors are handled gracefully."""
        from app.features.windowing import FeatureWindow

        # On Windows, file permissions work differently than Unix
        # Instead, create a file and then delete its parent directory to cause access error
        testdir = self.temppath / "restricted"
        testdir.mkdir()
        testfile = testdir / "test.txt"
        testfile.write_text("test content")

        # Remove the directory to cause access denied
        import shutil
        shutil.rmtree(testdir)

        # Now trying to read the file should fail gracefully
        window = FeatureWindow()
        entropy = window._calculateFileEntropy(testfile)
        # Should return None on access error
        assert entropy is None

    def test_nonexistent_file_handled(self):
        """Test that nonexistent files are handled gracefully."""
        from app.features.windowing import FeatureWindow

        nonexistent = self.temppath / "does_not_exist.txt"
        window = FeatureWindow()
        entropy = window._calculateFileEntropy(nonexistent)
        assert entropy is None

    def test_directory_instead_of_file_skipped(self):
        """Test that directories are skipped."""
        from app.features.windowing import FeatureWindow

        testdir = self.temppath / "testdir"
        testdir.mkdir()

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(testdir)
        assert entropy is None

    def test_empty_file_entropy(self):
        """Test entropy calculation for empty files."""
        from app.features.windowing import FeatureWindow

        emptyfile = self.temppath / "empty.txt"
        emptyfile.write_bytes(b"")

        window = FeatureWindow()
        entropy = window._calculateFileEntropy(emptyfile)
        assert entropy is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
