"""Generate harmless, non-sensitive files for collector experiments."""

import argparse
import json
import random
from pathlib import Path


fileTypes = {
    "txt": b"Generated benign test content.\n",
    "csv": b"name,value\nexample,1\n",
    "json": b'{"generated": true, "value": 1}\n',
    "doc": b"Generated document-like test content.\n",
    "jpg": b"Generated image-like test content.\n",
    "pdf": b"Generated PDF-like test content.\n",
}


def generateTestFiles(
    outputDirectory: Path,
    fileCount: int,
    seed: int = 42,
    minBytes: int = 128,
    maxBytes: int = 16384,
) -> int:
    if fileCount < 1 or fileCount > 100000:
        raise ValueError("fileCount must be between 1 and 100000")
    if minBytes < 1 or maxBytes < minBytes:
        raise ValueError("minBytes and maxBytes are invalid")
    outputDirectory = outputDirectory.resolve()
    outputDirectory.mkdir(parents=True, exist_ok=True)
    randomGenerator = random.Random(seed)
    typeNames = tuple(fileTypes)
    for index in range(fileCount):
        typeName = typeNames[randomGenerator.randrange(len(typeNames))]
        filePath = outputDirectory / f"sample{index:06d}.{typeName}"
        targetSize = randomGenerator.randint(minBytes, maxBytes)
        prefix = fileTypes[typeName] + f"sample={index}\n".encode("ascii")
        repeatedContent = (prefix * ((targetSize // len(prefix)) + 1))[:targetSize]
        filePath.write_bytes(repeatedContent)
    return fileCount


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate safe test files")
    parser.add_argument("--outputDirectory", default="testFiles")
    parser.add_argument("--files", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--minBytes", type=int, default=128)
    parser.add_argument("--maxBytes", type=int, default=16384)
    return parser.parse_args()


def main() -> int:
    arguments = getArguments()
    count = generateTestFiles(
        Path(arguments.outputDirectory),
        arguments.files,
        arguments.seed,
        arguments.minBytes,
        arguments.maxBytes,
    )
    print(json.dumps({"generated": count, "directory": str(Path(arguments.outputDirectory).resolve())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
