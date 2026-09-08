"""Generate ransomware-like file activity in an explicitly marked lab folder.

The simulator creates, modifies, and renames disposable sample files. It does
not encrypt, delete, or access files outside the selected lab directory.
"""

import argparse
import os
import secrets
from pathlib import Path


markerFile = ".lab-simulation"


def getArguments():
    parser = argparse.ArgumentParser(
        description="Generate safe file activity for collector testing."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="./test_files",
        help="Disposable lab directory (default: ./test_files)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of sample files to create or modify (default: 10)",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create the directory and marker before running the simulation.",
    )
    return parser.parse_args()


def validateDirectory(directory, initialize=False):
    labDirectory = Path(directory).resolve()

    if initialize:
        labDirectory.mkdir(parents=True, exist_ok=True)
        (labDirectory / markerFile).touch(exist_ok=True)

    if not labDirectory.is_dir():
        raise ValueError(f"Lab directory does not exist: {labDirectory}")

    if not (labDirectory / markerFile).is_file():
        raise ValueError(
            f"Refusing to operate without {markerFile} in {labDirectory}. "
            "Use --init only for a disposable lab directory."
        )

    return labDirectory


def runSimulation(labDirectory, count):
    if count < 1 or count > 1000:
        raise ValueError("count must be between 1 and 1000")

    for index in range(count):
        samplePath = labDirectory / f"sample_{index:04d}.txt"
        samplePath.write_bytes(secrets.token_bytes(512))

        renamedPath = labDirectory / f"sample_{index:04d}.lab"
        os.replace(samplePath, renamedPath)
        renamedPath.write_bytes(secrets.token_bytes(512))

    print(f"Generated activity for {count} disposable files in {labDirectory}")


def main():
    arguments = getArguments()
    try:
        labDirectory = validateDirectory(arguments.directory, arguments.init)
        runSimulation(labDirectory, arguments.count)
    except (OSError, ValueError) as error:
        raise SystemExit(f"Simulation stopped: {error}") from error


if __name__ == "__main__":
    main()