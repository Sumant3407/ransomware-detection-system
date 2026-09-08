# Ransomware Behavior Data Collector
import os
import csv
import time
import math
import argparse
import psutil
from datetime import datetime

from app.domain.schemas import featureColumns


# Module: Configuration

monitorDirectory = r"./testFiles"
outputFile = "./data/ransomwareBehaviorDataset.csv"

collectionInterval = 1
label = "Benign"

# Number of files whose names are displayed in the terminal
maxDisplayedFiles = 5


# Module: File Entropy Calculation

def calculateEntropy(filePath, maxBytes=4096):
    """
    Calculate Shannon entropy for a file.

    Entropy is useful as a behavioral feature because
    encrypted/compressed data can have high entropy.
    """

    try:
        with open(filePath, "rb") as file:
            data = file.read(maxBytes)

        if not data:
            return 0.0

        frequency = [0] * 256

        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        dataLength = len(data)

        for count in frequency:
            if count > 0:
                probability = count / dataLength
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except (
        PermissionError,
        FileNotFoundError,
        OSError
    ):
        return 0.0


# Module: Directory Snapshot

def getFileSnapshot(directory):
    """
    Capture the current state of files in a directory.
    """

    snapshot = {}

    if not os.path.exists(directory):
        return snapshot

    for root, _, files in os.walk(directory):

        for fileName in files:

            filePath = os.path.join(root, fileName)

            try:
                fileStats = os.stat(filePath)

                snapshot[filePath] = {
                    "size": fileStats.st_size,
                    "modifiedTime": fileStats.st_mtime
                }

            except (
                PermissionError,
                FileNotFoundError,
                OSError
            ):
                continue

    return snapshot


# Module: File Activity Detection

def compareSnapshots(previousSnapshot, currentSnapshot):

    previousFiles = set(previousSnapshot.keys())
    currentFiles = set(currentSnapshot.keys())

    createdFiles = currentFiles - previousFiles
    deletedFiles = previousFiles - currentFiles

    modifiedFiles = set()

    for filePath in previousFiles & currentFiles:

        oldFile = previousSnapshot[filePath]
        newFile = currentSnapshot[filePath]

        if (
            oldFile["size"] != newFile["size"]
            or oldFile["modifiedTime"] != newFile["modifiedTime"]
        ):
            modifiedFiles.add(filePath)

    # This is an approximation.
    # A reliable rename detector requires OS-level telemetry.
    renameCount = min(
        len(createdFiles),
        len(deletedFiles)
    )

    return {
        "created": createdFiles,
        "deleted": deletedFiles,
        "modified": modifiedFiles,
        "renamed": renameCount
    }


# Module: Network Monitoring

def getNetworkStatistics(previousNetworkBytes):

    networkStats = psutil.net_io_counters()

    totalNetworkBytes = (
        networkStats.bytes_sent +
        networkStats.bytes_recv
    )

    if previousNetworkBytes is None:
        networkBytesDelta = 0

    else:
        networkBytesDelta = max(
            0,
            totalNetworkBytes - previousNetworkBytes
        )

    return totalNetworkBytes, networkBytesDelta


# Module: System Resource Monitoring

def getSystemStatistics():

    cpuUsage = psutil.cpu_percent(interval=None)

    memoryInfo = psutil.virtual_memory()

    memoryUsage = memoryInfo.percent

    return cpuUsage, memoryUsage


# Module: Process Monitoring

def getProcessInformation():

    processNames = set()

    for process in psutil.process_iter(["name"]):

        try:

            processName = process.info["name"]

            if processName:
                processNames.add(processName)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processNames


# Module: Entropy Analysis

def calculateAverageEntropy(filePaths):

    if not filePaths:
        return 0.0

    entropyValues = []

    for filePath in filePaths:

        entropy = calculateEntropy(filePath)

        if entropy > 0:
            entropyValues.append(entropy)

    if not entropyValues:
        return 0.0

    return round(
        sum(entropyValues) / len(entropyValues),
        4
    )


# Module: CSV Dataset Management

csvFields = ["timestamp", *featureColumns, "label"]


def initializeCsv():

    outputDirectory = os.path.dirname(outputFile)
    if outputDirectory:
        os.makedirs(outputDirectory, exist_ok=True)

    if not os.path.exists(outputFile):

        with open(
            outputFile,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            csvWriter = csv.DictWriter(
                file,
                fieldnames=csvFields
            )

            csvWriter.writeheader()


# Module: Terminal Output

def displayFileList(title, filePaths):

    if not filePaths:
        return

    print(f"\n  {title}:")

    displayedFiles = list(filePaths)[
        :maxDisplayedFiles
    ]

    for filePath in displayedFiles:

        print(
            f"    • {os.path.basename(filePath)}"
        )

    remainingFiles = (
        len(filePaths) - len(displayedFiles)
    )

    if remainingFiles > 0:

        print(
            f"    • ... and {remainingFiles} more"
        )


def displayStatus(
    timestamp,
    activity,
    avgFileEntropy,
    cpuUsage,
    memoryUsage,
    networkBytes,
    processNames
):

    createdCount = len(activity["created"])
    modifiedCount = len(activity["modified"])
    deletedCount = len(activity["deleted"])
    renameCount = activity["renamed"]

    print("\n" + "=" * 72)

    print(f"TIME       : {timestamp}")
    print(f"LABEL      : {label}")
    print(f"MONITORING : {monitorDirectory}")

    print("-" * 72)

    print("FILE ACTIVITY")

    print(
        f"  Created       : {createdCount}"
    )

    print(
        f"  Modified      : {modifiedCount}"
    )

    print(
        f"  Renamed       : {renameCount}"
    )

    print(
        f"  Deleted       : {deletedCount}"
    )

    print("-" * 72)

    print("BEHAVIOR ANALYSIS")

    if modifiedCount >= 50:

        print(
            "  WARNING      : HIGH FILE MODIFICATION ACTIVITY"
        )

    elif modifiedCount >= 10:

        print(
            "  STATUS       : Elevated file modification activity"
        )

    else:

        print(
            "  STATUS       : Normal file modification activity"
        )

    if avgFileEntropy >= 7.0:

        print(
            "  ENTROPY      : HIGH"
        )

    elif avgFileEntropy > 0:

        print(
            f"  ENTROPY      : {avgFileEntropy:.2f}"
        )

    else:

        print(
            "  ENTROPY      : No modified-file data"
        )

    print("-" * 72)

    print("SYSTEM ACTIVITY")

    print(
        f"  CPU Usage    : {cpuUsage:.2f}%"
    )

    print(
        f"  Memory Usage : {memoryUsage:.2f}%"
    )

    print(
        f"  Network      : {networkBytes:,} bytes/sampled interval"
    )

    print(
        f"  Processes    : {len(processNames)}"
    )

    print("-" * 72)

    print("RECENT FILE OPERATIONS")

    displayFileList(
        "Created",
        activity["created"]
    )

    displayFileList(
        "Modified",
        activity["modified"]
    )

    displayFileList(
        "Deleted",
        activity["deleted"]
    )

    print("=" * 72)


# Module: Dataset Collection Engine

def collectData(sampleLimit=None):

    print("\n" + "=" * 72)

    print("       RANSOMWARE BEHAVIOR DATA COLLECTOR")

    print("=" * 72)

    print(f"Monitoring directory : {monitorDirectory}")
    print(f"Output CSV           : {outputFile}")
    print(f"Current label        : {label}")
    print(f"Sampling interval    : {collectionInterval} second(s)")

    print("\nStarting collector...")

    if not os.path.exists(monitorDirectory):

        print(
            "\nDirectory does not exist."
        )

        os.makedirs(monitorDirectory)

        print(
            f"Created: {monitorDirectory}"
        )

        print(
            "Add disposable test files before collecting data."
        )

    initializeCsv()

    previousSnapshot = getFileSnapshot(
        monitorDirectory
    )

    previousNetworkBytes = None

    modificationWindow = 0
    windowStartTime = time.time()

    totalSamples = 0

    print("\nCollector is running.")
    print("Perform activity inside the monitored directory.")
    print("Press CTRL+C to stop.\n")

    try:

        while sampleLimit is None or totalSamples < sampleLimit:

            time.sleep(collectionInterval)

            currentSnapshot = getFileSnapshot(
                monitorDirectory
            )

            activity = compareSnapshots(
                previousSnapshot,
                currentSnapshot
            )

            createdCount = len(activity["created"])
            modifiedCount = len(activity["modified"])
            deletedCount = len(activity["deleted"])

            modificationWindow += modifiedCount

            currentTime = time.time()

            elapsedTime = (
                currentTime - windowStartTime
            )

            # Calculate a rolling one-minute modification rate.
            if elapsedTime >= 60:

                filesModifiedPerMinute = (
                    modificationWindow /
                    (elapsedTime / 60)
                )

                modificationWindow = 0
                windowStartTime = currentTime

            else:

                filesModifiedPerMinute = modificationWindow

            # Module: Entropy Measurement
            avgFileEntropy = calculateAverageEntropy(
                activity["modified"]
            )

            # Module: System Statistics
            cpuUsage, memoryUsage = (
                getSystemStatistics()
            )

            # Module: Network Statistics
            (
                previousNetworkBytes,
                networkBytes
            ) = getNetworkStatistics(
                previousNetworkBytes
            )

            # Module: Process Statistics
            processNames = getProcessInformation()

            # Module: Dataset Record Creation
            dataRow = {

                "timestamp":
                    datetime.now().isoformat(),

                "fileReadCount":
                    0,

                "fileWriteCount":
                    modifiedCount,

                "fileCreateCount":
                    createdCount,

                "fileRenameCount":
                    activity["renamed"],

                "fileDeleteCount":
                    deletedCount,

                "filesModifiedPerMinute":
                    round(
                        filesModifiedPerMinute,
                        2
                    ),

                "uniqueDirectoriesModified":
                    len({os.path.dirname(path) for path in activity["modified"]}),

                "uniqueExtensionsModified":
                    len({os.path.splitext(path)[1].lower() for path in activity["modified"] if os.path.splitext(path)[1]}),

                "extensionChangeCount":
                    0,

                "averageFileEntropy":
                    avgFileEntropy,

                "entropyChangeRate":
                    avgFileEntropy,

                "processCpuUsage":
                    round(
                        cpuUsage,
                        2
                    ),

                "processMemoryUsage":
                    round(
                        memoryUsage,
                        2
                    ),

                "processLifetime":
                    0,

                "networkBytes":
                    networkBytes,

                "networkConnectionCount":
                    0,

                "label":
                    label
            }

            # Module: CSV Data Storage
            with open(
                outputFile,
                "a",
                newline="",
                encoding="utf-8"
            ) as file:

                csvWriter = csv.DictWriter(
                    file,
                    fieldnames=csvFields
                )

                csvWriter.writerow(dataRow)

            totalSamples += 1

            # Module: Live Monitoring Dashboard
            displayStatus(
                dataRow["timestamp"],
                activity,
                avgFileEntropy,
                cpuUsage,
                memoryUsage,
                networkBytes,
                processNames
            )

            print(
                f"Dataset samples collected: {totalSamples}"
            )

            previousSnapshot = currentSnapshot

    except KeyboardInterrupt:

        print("\n\n" + "=" * 72)
        print("COLLECTOR STOPPED")
        print("=" * 72)

        print(
            f"Total samples : {totalSamples}"
        )

        print(
            f"Dataset       : {outputFile}"
        )

        print("=" * 72)


# Module: Program Entry Point

def getArguments():
    parser = argparse.ArgumentParser(description="Collect safe filesystem behavior data")
    parser.add_argument("--directory", default=monitorDirectory)
    parser.add_argument("--outputFile", default=outputFile)
    parser.add_argument("--label", default=label, choices=("Benign", "RANSOMWARE_LIKE"))
    parser.add_argument("--interval", type=float, default=collectionInterval)
    parser.add_argument("--samples", type=int, default=None)
    return parser.parse_args()


def configureCollector(arguments):
    global monitorDirectory, outputFile, label, collectionInterval
    monitorDirectory = arguments.directory
    outputFile = arguments.outputFile
    label = arguments.label
    collectionInterval = max(0.1, arguments.interval)


if __name__ == "__main__":
    arguments = getArguments()
    configureCollector(arguments)
    collectData(arguments.samples)