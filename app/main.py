"""Command-line entry point for the detection application foundation."""

import argparse
from pathlib import Path

from app import applicationVersion
from app.config.configuration import getDataDirectory, getProjectRoot, initializeDirectories, loadConfiguration, resolveMonitoringPath
from app.storage.sqliteStore import initializeDatabase
from app.logging.logger import createLogger
from app.runtime.controller import DetectionController


def getArguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline ransomware behavior detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m app.main --interactive          Launch interactive menu
  python -m app.main --monitor --samples 10 Run 10 monitoring samples
  python -m app.main --status               Show current status
  python -m app.main --health               Run system health check
  python -m app.main --health --json        System health report in JSON format
  python -m app.main --metrics              Show live system & detection metrics
  python -m app.main --scan                 Perform one-time scan
        """
    )
    parser.add_argument("--status", action="store_true", help="Show detailed protection status")
    parser.add_argument("--health", action="store_true", help="Run comprehensive subsystem health check")
    parser.add_argument("--metrics", action="store_true", help="Display live telemetry and process metrics")
    parser.add_argument("--json", action="store_true", help="Output health, metrics, or status in JSON format")
    parser.add_argument("--version", action="store_true", help="Show application version")
    parser.add_argument("--ui", "-u", action="store_true", help="Launch integrated Electron Desktop CRT Terminal Station")
    parser.add_argument("--gui", "-g", action="store_true", help="Launch Desktop Graphical SOC Dashboard")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive menu interface")
    parser.add_argument("--monitor", action="store_true", help="Run headless monitoring session")
    parser.add_argument("--samples", type=int, default=None, help="Number of monitoring samples (default: unlimited)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between monitoring samples")
    parser.add_argument("--scan", action="store_true", help="Perform a one-time scan")
    parser.add_argument("--history", action="store_true", help="Show detection history")
    parser.add_argument("--forensics", action="store_true", help="Show forensic investigation snapshots")
    parser.add_argument("--snapshot-id", type=int, default=None, help="Inspect specific forensic snapshot by ID")
    parser.add_argument("--prune-days", type=int, default=None, help="Prune historical events older than N days")
    parser.add_argument("--optimize-db", action="store_true", help="Run SQLite database optimization and WAL checkpoint")
    parser.add_argument("--validate-config", type=str, default=None, help="Validate a candidate JSON configuration file")
    parser.add_argument("--swap-model", type=str, default=None, help="Validate and test swapping active ML model")
    parser.add_argument("--hot-reload", action="store_true", help="Enable dynamic background hot-reload of config and model files")
    parser.add_argument("--demo", choices=["wizard", "benign", "normal", "attack", "clean"], nargs="?", const="wizard", default=None, help="Execute safe demonstration workflows (generate benign files, simulate normal work, or safe lab attack)")
    parser.add_argument("--demo-count", type=int, default=25, help="Number of files to target during demo (default: 25)")
    parser.add_argument("--demo-steps", type=int, default=10, help="Number of action steps for normal work simulation (default: 10)")
    parser.add_argument("--config", action="store_true", help="Open configuration interface")
    return parser.parse_args()


def initializeApplication() -> tuple[dict, Path]:
    configuration = loadConfiguration()
    initializeDirectories()
    for pathValue in configuration["monitoring"]["paths"]:
        resolvedPath = resolveMonitoringPath(pathValue)
        resolvedPath.mkdir(parents=True, exist_ok=True)
    databasePath = getDataDirectory() / "database" / "detector.sqlite3"
    connection = initializeDatabase(databasePath)
    connection.close()
    createLogger(getDataDirectory() / "logs", configuration["logging"]["level"])
    return configuration, databasePath


def main() -> int:
    arguments = getArguments()

    # Version check
    if arguments.version:
        print(f"Ransomware Detection System v{applicationVersion}")
        return 0

    # Initialize application
    try:
        configuration, databasePath = initializeApplication()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Initialization failed: {error}")
        return 1

    # Integrated Electron Desktop CRT Station mode
    if arguments.ui:
        return launchIntegratedDesktopUi()

    # Desktop GUI mode
    if arguments.gui:
        try:
            from app.ui.mainWindow import runGui
            return runGui()
        except Exception as error:
            print(f"Desktop GUI launch failed: {error}")
            return 1

    # Interactive menu mode
    if arguments.interactive:
        try:
            from app.ui.interactive import run_interactive
            return run_interactive()
        except ImportError as error:
            print(f"Interactive interface unavailable: {error}")
            return 1

    # Status display
    if arguments.status:
        return showDetailedStatus(configuration, databasePath, jsonOutput=arguments.json)

    # Health check
    if arguments.health:
        return showHealthReport(configuration, databasePath, jsonOutput=arguments.json)

    # Telemetry metrics
    if arguments.metrics:
        return showMetrics(configuration, databasePath, jsonOutput=arguments.json)

    # Detection history
    if arguments.history:
        return showHistory(databasePath, jsonOutput=arguments.json)

    # Forensic snapshots & process tree evidence
    if arguments.forensics or arguments.snapshot_id is not None:
        return showForensics(databasePath, snapshotId=arguments.snapshot_id, jsonOutput=arguments.json)

    # Database maintenance & pruning
    if arguments.prune_days is not None:
        return performDatabasePruning(databasePath, days=arguments.prune_days, jsonOutput=arguments.json)

    # Database optimization
    if arguments.optimize_db:
        return performDatabaseOptimization(databasePath, jsonOutput=arguments.json)

    # Configuration file preflight validation
    if arguments.validate_config:
        return performConfigValidation(Path(arguments.validate_config), jsonOutput=arguments.json)

    # Model hot-swap validation
    if arguments.swap_model:
        return performModelSwapValidation(Path(arguments.swap_model), jsonOutput=arguments.json)

    # Configuration interface
    if arguments.config:
        try:
            from app.ui.interactive import InteractiveCLI
            cli = InteractiveCLI()
            cli.configuration_menu()
            return 0
        except ImportError as error:
            print(f"Configuration interface unavailable: {error}")
            return 1

    # Demonstration & Safe Lab Workloads
    if arguments.demo is not None:
        return performDemoAction(
            action=arguments.demo,
            count=arguments.demo_count,
            steps=arguments.demo_steps,
            jsonOutput=arguments.json,
        )

    # One-time scan
    if arguments.scan:
        return performScan(configuration, databasePath, jsonOutput=arguments.json)

    # Headless monitoring
    if arguments.monitor:
        return runHeadlessMonitoring(configuration, databasePath, arguments)

    # Default: show help or run interactive mode
    print(f"Ransomware Detection System v{applicationVersion}")
    print("Use --help to see available options")
    print("Use --interactive to launch the menu interface")
    print("Use --status to view current status")
    return 0


def showDetailedStatus(configuration: dict, databasePath: Path, jsonOutput: bool = False) -> int:
    """Show detailed system status."""
    import json
    import sqlite3
    from app.ui.console import ConsoleDisplay, print_status_table
    from app.detection.predictor import ModelPredictor, ModelValidationError

    monitoringPaths = [resolveMonitoringPath(p) for p in configuration["monitoring"]["paths"]]
    modelPath = Path(configuration["model"].get("path", ""))
    if not modelPath.is_absolute():
        modelPath = getProjectRoot() / modelPath

    modelValid = False
    modelError = None
    if modelPath.is_file():
        try:
            ModelPredictor(modelPath)
            modelValid = True
        except ModelValidationError as error:
            modelError = str(error)

    total_events = 0
    total_detections = 0
    total_sessions = 0
    try:
        connection = sqlite3.connect(databasePath)
        total_events = connection.execute("SELECT COUNT(*) FROM fileEvents").fetchone()[0]
        total_detections = connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        total_sessions = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        connection.close()
    except Exception:
        pass

    if jsonOutput:
        payload = {
            "version": applicationVersion,
            "monitoringPaths": [str(p) for p in monitoringPaths],
            "intervalSeconds": configuration["monitoring"].get("intervalSeconds", 1),
            "sensitivity": configuration["monitoring"].get("sensitivity", "medium"),
            "alertCooldownSeconds": configuration["monitoring"].get("alertCooldownSeconds", 60),
            "model": {
                "path": str(modelPath),
                "exists": modelPath.is_file(),
                "valid": modelValid,
                "error": modelError,
            },
            "database": {
                "path": str(databasePath),
                "totalEvents": total_events,
                "totalDetections": total_detections,
                "totalSessions": total_sessions,
            },
        }
        print(json.dumps(payload, indent=2))
        return 0

    console = ConsoleDisplay()
    print()
    print(console.format_header("RANSOMWARE DETECTION SYSTEM - STATUS"))

    # Configuration
    print(f"{console.BOLD}Configuration:{console.RESET}")
    if len(monitoringPaths) == 1:
        print(console.format_status_line("  Monitoring Path", str(monitoringPaths[0])))
    else:
        print(console.format_status_line("  Monitoring Paths", f"{len(monitoringPaths)} active"))
        for idx, p in enumerate(monitoringPaths, 1):
            print(console.format_status_line(f"    [{idx}]", str(p)))
    print(console.format_status_line(
        "  Interval",
        f"{configuration['monitoring'].get('intervalSeconds', 1)}s"
    ))
    print(console.format_status_line(
        "  Sensitivity",
        configuration["monitoring"]["sensitivity"]
    ))
    print()

    # Model status
    print(f"{console.BOLD}Model Status:{console.RESET}")
    if modelPath.is_file():
        if modelValid:
            print(console.format_status_line("  Status", "Valid", console.GREEN))
            print(console.format_status_line("  Path", str(modelPath)))
        else:
            print(console.format_status_line("  Status", f"Invalid: {modelError}", console.RED))
    else:
        print(console.format_status_line("  Status", "No model found", console.YELLOW))
    print()

    # Database statistics
    print(f"{console.BOLD}Database Statistics:{console.RESET}")
    print(console.format_status_line("  Total Sessions", str(total_sessions)))
    print(console.format_status_line("  Total File Events", str(total_events)))
    print(console.format_status_line("  Total Detections", str(total_detections)))

    print()
    return 0


def showHealthReport(configuration: dict, databasePath: Path, jsonOutput: bool = False) -> int:
    """Run comprehensive system health check and output summary or JSON."""
    import json
    from app.operations.healthCheck import HealthStatus, formatHealthSummary, runHealthCheck

    try:
        report = runHealthCheck(configuration=configuration, databasePath=databasePath)
        if jsonOutput:
            print(json.dumps(report.toDict(), indent=2))
        else:
            print()
            print(formatHealthSummary(report))
            print()

        return 0 if report.status != HealthStatus.UNHEALTHY else 2
    except Exception as error:
        if jsonOutput:
            print(json.dumps({"status": "unhealthy", "error": str(error)}, indent=2))
        else:
            print(f"Health check execution failed: {error}")
        return 1


def showMetrics(configuration: dict, databasePath: Path, jsonOutput: bool = False) -> int:
    """Collect and display process and detection pipeline metrics."""
    import json
    from dataclasses import asdict
    from app.operations.healthCheck import HealthChecker

    try:
        checker = HealthChecker(configuration=configuration, databasePath=databasePath)
        metrics = checker.collectMetrics()

        if jsonOutput:
            print(json.dumps(asdict(metrics), indent=2))
        else:
            from app.ui.console import ConsoleDisplay
            console = ConsoleDisplay()
            print()
            print(console.format_header("SYSTEM & PIPELINE TELEMETRY"))
            print(f"{console.BOLD}Process Telemetry:{console.RESET}")
            print(console.format_status_line("  CPU Usage", f"{metrics.processCpuPercent:.1f}%"))
            print(console.format_status_line("  Memory (RSS)", f"{metrics.processMemoryRssMb:.1f} MB"))
            print(console.format_status_line("  Memory (VMS)", f"{metrics.processMemoryVmsMb:.1f} MB"))
            print(console.format_status_line("  Active Threads", str(metrics.threadCount)))
            print(console.format_status_line("  Open Handles", str(metrics.openFileHandles)))
            print(console.format_status_line("  Uptime", f"{metrics.processUptimeSeconds:.1f}s"))
            print()
            print(f"{console.BOLD}Detection Pipeline Telemetry:{console.RESET}")
            print(console.format_status_line("  Total Sessions", str(metrics.totalSessions)))
            print(console.format_status_line("  Total File Events", str(metrics.totalFileEvents)))
            print(console.format_status_line("  Total Detections", str(metrics.totalDetections)))
            print(console.format_status_line("  Total Alerts Raised", str(metrics.totalAlerts)))
            print(console.format_status_line("  Unconsumed Feedback", str(metrics.unconsumedFeedbackCount)))
            print(console.format_status_line("  Last Retraining Status", metrics.lastRetrainingStatus or "None"))
            print()

        return 0
    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            print(f"Failed to collect telemetry: {error}")
        return 1


def showHistory(databasePath: Path, jsonOutput: bool = False) -> int:
    """Show detection history."""
    import json
    import sqlite3
    from app.ui.console import ConsoleDisplay, print_status_table

    try:
        connection = sqlite3.connect(databasePath)
        rows = connection.execute(
            "SELECT detectionId, occurredAt, classification, riskScore, actionTaken "
            "FROM detections ORDER BY detectionId DESC LIMIT 50"
        ).fetchall()
        connection.close()

        if jsonOutput:
            detections = []
            for r in rows:
                detections.append({
                    "detectionId": r[0],
                    "occurredAt": r[1],
                    "classification": r[2],
                    "riskScore": float(r[3]),
                    "actionTaken": r[4],
                })
            print(json.dumps(detections, indent=2))
            return 0

        console = ConsoleDisplay()
        print()
        print(console.format_header("DETECTION HISTORY"))

        if not rows:
            print(f"{console.DIM}No detections recorded.{console.RESET}\n")
        else:
            print_status_table(
                ["Timestamp", "Classification", "Risk Score", "Action"],
                [[row[1], row[2], f"{float(row[3]):.4f}", row[4]] for row in rows]
            )
            print(f"{console.DIM}Showing up to 50 most recent detections{console.RESET}")

        print()
        return 0
    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            print(f"Error reading history: {error}")
        return 1


def showForensics(databasePath: Path, snapshotId: int | None = None, jsonOutput: bool = False) -> int:
    """Display forensic snapshots or detailed evidence report."""
    import json
    import sqlite3
    from app.forensics.forensicCollector import ForensicCollector
    from app.ui.console import ConsoleDisplay, print_status_table

    console = ConsoleDisplay()
    collector = ForensicCollector()

    try:
        connection = sqlite3.connect(databasePath)

        if snapshotId is not None:
            snapshot = collector.getSnapshotById(connection, snapshotId)
            connection.close()

            if snapshot is None:
                if jsonOutput:
                    print(json.dumps({"error": f"Snapshot ID {snapshotId} not found"}, indent=2))
                else:
                    console.print_banner(f"Forensic snapshot #{snapshotId} not found", "error")
                return 1

            if jsonOutput:
                print(snapshot.formatJson())
            else:
                print()
                print(snapshot.formatConsoleReport())
                print()
            return 0

        # List recent snapshots
        snapshots = collector.getRecentSnapshots(connection, limit=25)
        connection.close()

        if jsonOutput:
            print(json.dumps([s.toDict() for s in snapshots], indent=2))
            return 0

        print()
        print(console.format_header("FORENSIC EVIDENCE SNAPSHOTS"))

        if not snapshots:
            print(f"{console.DIM}No forensic snapshots recorded.{console.RESET}\n")
        else:
            table_data = []
            for s in snapshots:
                table_data.append([
                    str(s.snapshotId),
                    str(s.detectionId or "N/A"),
                    s.capturedAt[:19],
                    s.processName or "unknown",
                    str(s.processId or "N/A"),
                    s.classification.upper(),
                    f"{s.riskScore:.4f}",
                    str(len(s.processTree)),
                ])

            print_status_table(
                ["ID", "DetID", "Timestamp", "Process", "PID", "Class", "Risk", "Tree Depth"],
                table_data,
            )
            print(f"{console.DIM}Use --snapshot-id <ID> to inspect full forensic report and process lineage.{console.RESET}\n")

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            console.print_banner(f"Error accessing forensic database: {error}", "error")
        return 1


def performDatabasePruning(databasePath: Path, days: int = 30, jsonOutput: bool = False) -> int:
    """Prune historical events and telemetry records older than specified retention."""
    import json
    import sqlite3
    from app.storage.sqliteStore import pruneOldData
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()

    try:
        connection = sqlite3.connect(databasePath)
        counts = pruneOldData(connection, retentionDays=days, preserveThreats=True)
        connection.close()

        if jsonOutput:
            print(json.dumps({"retentionDays": days, "pruned": counts}, indent=2))
        else:
            print()
            console.print_banner(f"Database Retention Pruning (Older than {days} days)", "info")
            print(f"{console.BOLD}Pruned Records:{console.RESET}")
            for table, count in counts.items():
                print(console.format_status_line(f"  {table}", f"{count} row(s) deleted"))
            print()

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            console.print_banner(f"Database pruning failed: {error}", "error")
        return 1


def performDatabaseOptimization(databasePath: Path, jsonOutput: bool = False) -> int:
    """Optimize SQLite indexes, update statistics, and checkpoint WAL."""
    import json
    import sqlite3
    from app.storage.sqliteStore import optimizeDatabase
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()

    try:
        connection = sqlite3.connect(databasePath)
        stats = optimizeDatabase(connection)
        connection.close()

        if jsonOutput:
            print(json.dumps(stats, indent=2))
        else:
            print()
            console.print_banner("Database Optimization & Index Analysis Complete", "success")
            print(console.format_status_line("  Status", stats.get("status", "unknown")))
            print(console.format_status_line("  Total DB Size", f"{stats.get('totalSizeBytes', 0) / 1024:.2f} KB"))
            print(console.format_status_line("  Free Space", f"{stats.get('freeSizeBytes', 0) / 1024:.2f} KB"))
            print(console.format_status_line("  Page Count", str(stats.get("pageCount", 0))))
            print()

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            console.print_banner(f"Database optimization failed: {error}", "error")
        return 1


def performConfigValidation(configPath: Path, jsonOutput: bool = False) -> int:
    """Perform preflight validation on a candidate configuration file."""
    import json
    from app.config.configuration import loadConfiguration, validateConfiguration
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()
    resolvedPath = Path(configPath).resolve()

    try:
        if not resolvedPath.is_file():
            raise FileNotFoundError(f"Configuration file not found: {resolvedPath}")

        candidateConfig = loadConfiguration(resolvedPath)
        validateConfiguration(candidateConfig)

        if jsonOutput:
            print(json.dumps({
                "valid": True,
                "path": str(resolvedPath),
                "sections": list(candidateConfig.keys()),
                "monitoringPaths": candidateConfig.get("monitoring", {}).get("paths", []),
            }, indent=2))
        else:
            print()
            console.print_banner(f"Configuration Validation Passed: {resolvedPath.name}", "success")
            print(console.format_status_line("  Path", str(resolvedPath)))
            print(console.format_status_line("  Sections", ", ".join(candidateConfig.keys())))
            print(console.format_status_line("  Monitored Paths", str(len(candidateConfig.get("monitoring", {}).get("paths", [])))))
            print(console.format_status_line("  Alert Cooldown", f"{candidateConfig.get('monitoring', {}).get('alertCooldownSeconds', 60)}s"))
            print()

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({
                "valid": False,
                "path": str(resolvedPath),
                "error": str(error),
            }, indent=2))
        else:
            print()
            console.print_banner(f"Configuration Validation Failed: {error}", "error")
            print()
        return 1


def performModelSwapValidation(modelPath: Path, jsonOutput: bool = False) -> int:
    """Preflight test candidate ML model artifact for live zero-downtime hot-swap."""
    import json
    from app.detection.predictor import ModelPredictor
    from app.domain.schemas import featureColumns
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()
    resolvedPath = Path(modelPath).resolve()

    try:
        if not resolvedPath.is_file():
            raise FileNotFoundError(f"Model artifact file not found: {resolvedPath}")

        # 1. Preflight load & decrypt candidate predictor
        predictor = ModelPredictor(resolvedPath)

        # 2. Preflight inference smoke test
        testSample = {col: 0.0 for col in featureColumns}
        prob = predictor.predictProbability(testSample)

        modelType = type(predictor.model).__name__ if predictor.model else "Unknown"

        if jsonOutput:
            print(json.dumps({
                "valid": True,
                "modelPath": str(resolvedPath),
                "modelType": modelType,
                "featureCount": len(featureColumns),
                "testInferenceProbability": prob,
                "status": "Ready for live hot-swap",
            }, indent=2))
        else:
            print()
            console.print_banner(f"Model Preflight Validation Passed: {resolvedPath.name}", "success")
            print(console.format_status_line("  Model Path", str(resolvedPath)))
            print(console.format_status_line("  Model Type", modelType))
            print(console.format_status_line("  Feature Schema", f"{len(featureColumns)} features verified"))
            print(console.format_status_line("  Inference Test", f"Success (baseline prob: {prob:.4f})"))
            print()

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({
                "valid": False,
                "modelPath": str(resolvedPath),
                "error": str(error),
            }, indent=2))
        else:
            print()
            console.print_banner(f"Model Hot-Swap Validation Failed: {error}", "error")
            print()
        return 1


def performDemoAction(
    action: str,
    count: int = 25,
    steps: int = 10,
    jsonOutput: bool = False,
) -> int:
    """Execute safe demonstration and lab simulation action from CLI."""
    import json
    from app.operations.demoEngine import DemoEngine
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()
    engine = DemoEngine()

    try:
        if action == "wizard":
            print()
            print(console.format_header("SAFE DEMO & LABORATORY WORKLOAD WIZARD"))
            print("Select demonstration action:")
            print("  [1] Generate Benign Documents (.docx, .xlsx, .pdf, .txt, .csv, .json, .py, .jpg)")
            print("  [2] Simulate Normal Office User Activity (Low-velocity edits & saves)")
            print("  [3] Simulate Sandboxed Ransomware Attack (Rapid mass renames & high-entropy writes)")
            print("  [4] Clean & Reset Demo Sandbox Directory")
            print("  [0] Cancel")
            print()
            choice = input(f"{console.CYAN}Select option [0-4]: {console.RESET}").strip()
            if choice == "1":
                action = "benign"
            elif choice == "2":
                action = "normal"
            elif choice == "3":
                action = "attack"
            elif choice == "4":
                action = "clean"
            else:
                print("Demo cancelled.")
                return 0

        if action == "benign":
            if not jsonOutput:
                print(f"\n{console.BOLD}[*] Generating {count} benign test documents in testFiles/...{console.RESET}")
            report = engine.generateBenignFiles(
                count=count,
                callback=None if jsonOutput else lambda c, t, n: print(f"  {console.GREEN}[+]{console.RESET} ({c}/{t}) Generated {n}"),
            )
            if jsonOutput:
                print(json.dumps({"action": "generate_benign", "created": report.filesCreated, "duration": report.durationSeconds, "directory": str(report.targetDirectory)}, indent=2))
            else:
                print()
                console.print_banner(f"Successfully generated {report.filesCreated} benign files in {report.durationSeconds:.2f}s", "success")
                print()
            return 0

        elif action == "normal":
            if not jsonOutput:
                print(f"\n{console.BOLD}[*] Simulating {steps} normal user activity steps in testFiles/...{console.RESET}")
            report = engine.simulateNormalActivity(
                steps=steps,
                delaySeconds=0.15,
                callback=None if jsonOutput else lambda c, t, d: print(f"  {console.CYAN}[+]{console.RESET} Step {c}/{t}: {d}"),
            )
            if jsonOutput:
                print(json.dumps({"action": "simulate_normal", "modified": report.filesModified, "created": report.filesCreated, "duration": report.durationSeconds}, indent=2))
            else:
                print()
                console.print_banner(f"Simulated {steps} normal user steps in {report.durationSeconds:.2f}s (Threat level: LOW)", "success")
                print()
            return 0

        elif action == "attack":
            if not jsonOutput:
                print(f"\n{console.BOLD}{console.RED}[!] Simulating safe ransomware attack on {count} files in testFiles/...{console.RESET}")
            report = engine.simulateRansomwareAttack(
                fileCount=count,
                callback=None if jsonOutput else lambda c, t, d: print(f"  {console.RED}[!]{console.RESET} {c}/{t}: {d}"),
            )
            if jsonOutput:
                print(json.dumps({"action": "simulate_ransomware", "renamed": report.filesRenamed, "modified": report.filesModified, "duration": report.durationSeconds}, indent=2))
            else:
                print()
                console.print_banner(f"Attack simulation complete ({report.filesRenamed} files renamed in {report.durationSeconds:.2f}s). Check detection alert!", "warning")
                print()
            return 0

        elif action == "clean":
            if not jsonOutput:
                print(f"\n{console.BOLD}[*] Cleaning demo sandbox directory...{console.RESET}")
            report = engine.cleanSandbox(
                callback=None if jsonOutput else lambda d: print(f"  {console.DIM}[-]{console.RESET} {d}"),
            )
            if jsonOutput:
                print(json.dumps({"action": "clean_sandbox", "deleted": report.filesDeleted, "duration": report.durationSeconds}, indent=2))
            else:
                print()
                console.print_banner(f"Cleaned {report.filesDeleted} files from demo sandbox", "success")
                print()
            return 0

        else:
            print(f"Unknown demo action: {action}")
            return 1

    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            print()
            console.print_banner(f"Demo failed: {error}", "error")
            print()
        return 1


def performScan(configuration: dict, databasePath: Path, jsonOutput: bool = False) -> int:
    """Perform one-time scan across all monitored paths."""
    import json
    from app.ui.console import ConsoleDisplay

    try:
        monitoringPaths = [resolveMonitoringPath(p) for p in configuration["monitoring"]["paths"]]
        modelPath = Path(configuration["model"].get("path", ""))
        if not modelPath.is_absolute():
            modelPath = getProjectRoot() / modelPath

        controller = DetectionController(
            monitoredPaths=monitoringPaths,
            databasePath=databasePath,
            modelPath=modelPath if modelPath.is_file() else None,
        )

        try:
            decision = controller.collectOnce()
        finally:
            controller.close()

        if jsonOutput:
            print(json.dumps({
                "level": str(decision.level.value if hasattr(decision.level, "value") else decision.level),
                "score": float(decision.score),
                "classification": str(decision.classification),
                "action": str(decision.action.value if hasattr(decision.action, "value") else decision.action),
            }, indent=2))
            return 0

        console = ConsoleDisplay()
        print()
        console.print_banner("Performing scan...", "info")

        print(f"{console.BOLD}Scan Results:{console.RESET}")
        print(console.format_status_line(
            "  Threat Level",
            decision.level.value.upper(),
            console.get_threat_color(decision.level.value)
        ))
        print(console.format_status_line("  Risk Score", f"{decision.score:.4f}"))
        print(console.format_status_line("  Classification", decision.classification))
        print()

        if decision.level.value in ("high", "critical"):
            console.print_banner("RANSOMWARE-LIKE ACTIVITY DETECTED!", "critical")
        elif decision.level.value == "medium":
            console.print_banner("Suspicious activity detected", "warning")
        else:
            console.print_banner("No threats detected", "success")

        return 0

    except Exception as error:
        if jsonOutput:
            print(json.dumps({"error": str(error)}, indent=2))
        else:
            console = ConsoleDisplay()
            console.print_banner(f"Scan failed: {error}", "error")
        return 1


def launchIntegratedDesktopUi() -> int:
    """Launch the integrated Electron Desktop CRT Terminal Station."""
    import shutil
    import subprocess
    from app.config.configuration import getProjectRoot

    projectRoot = getProjectRoot()
    npmPath = shutil.which("npm") or shutil.which("npm.cmd")

    if not npmPath:
        print("Node.js / npm is required to launch the Electron Desktop UI.")
        print("Please install Node.js (https://nodejs.org) or run the Python GUI via: python -m app.main --gui")
        return 1

    print("[*] Launching Ransomware Behavior Defense Station (CRT Electron Desktop)...")
    try:
        distElectronMain = projectRoot / "dist-electron" / "main.js"
        distIndex = projectRoot / "dist" / "index.html"
        if not distElectronMain.is_file() or not distIndex.is_file():
            print("[*] Compiling desktop UI assets...")
            subprocess.run([npmPath, "run", "build:electron"], cwd=str(projectRoot), check=True)
            subprocess.run([npmPath, "run", "build"], cwd=str(projectRoot), check=True)

        subprocess.run([npmPath, "run", "electron:preview"], cwd=str(projectRoot))
        return 0
    except Exception as error:
        print(f"Failed to launch Electron Desktop UI: {error}")
        return 1


def runHeadlessMonitoring(configuration: dict, databasePath: Path, arguments: argparse.Namespace) -> int:
    """Run headless monitoring session for all configured paths."""
    from app.ui.console import ConsoleDisplay, LiveMonitorDisplay
    from app.runtime.genericWorker import MonitoringWorker
    from datetime import datetime, timedelta
    import time

    console = ConsoleDisplay()

    monitoringPaths = [resolveMonitoringPath(p) for p in configuration["monitoring"]["paths"]]
    modelPath = Path(configuration["model"].get("path", ""))
    if not modelPath.is_absolute():
        modelPath = getProjectRoot() / modelPath

    # Check if live display mode
    use_live_display = arguments.samples is None  # Unlimited = live display

    if use_live_display:
        print()
        console.print_banner("Starting live monitoring (Press Ctrl+C to stop)...", "info")
        time.sleep(1)

        display = LiveMonitorDisplay()
        display.start()

        worker = MonitoringWorker(
            monitoredPaths=monitoringPaths,
            databasePath=databasePath,
            modelPath=modelPath if modelPath.is_file() else None,
            intervalSeconds=arguments.interval,
            enableHotReload=getattr(arguments, "hot_reload", False),
        )

        session_start = datetime.now()

        try:
            worker.start()

            while worker.is_running():
                # Get stats from database
                import sqlite3
                connection = sqlite3.connect(databasePath)

                files_changed = connection.execute(
                    """
                    SELECT COUNT(*) FROM fileEvents
                    WHERE sessionId = (SELECT sessionId FROM sessions ORDER BY sessionId DESC LIMIT 1)
                    """
                ).fetchone()[0]

                detections = connection.execute(
                    "SELECT COUNT(*) FROM detections WHERE classification != 'benign'"
                ).fetchone()[0]

                latest = connection.execute(
                    "SELECT riskScore FROM detections ORDER BY detectionId DESC LIMIT 1"
                ).fetchone()

                last_event_row = connection.execute(
                    "SELECT action, occurredAt FROM fileEvents ORDER BY eventId DESC LIMIT 1"
                ).fetchone()

                connection.close()

                threat_level = "low"
                risk_score = 0.0

                if latest:
                    risk_score = float(latest[0])
                    if risk_score >= 0.85:
                        threat_level = "critical"
                    elif risk_score >= 0.65:
                        threat_level = "high"
                    elif risk_score >= 0.40:
                        threat_level = "medium"

                last_event = ""
                if last_event_row:
                    last_event = f"{last_event_row[0]} at {last_event_row[1]}"

                uptime = datetime.now() - session_start
                hours, remainder = divmod(int(uptime.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"

                model_status = "Active" if modelPath.is_file() else "No model (rule-based only)"

                monitoring_label = str(monitoringPaths[0]) if len(monitoringPaths) == 1 else f"{len(monitoringPaths)} paths ({', '.join(p.name for p in monitoringPaths)})"

                display.update(
                    protected=True,
                    threat_level=threat_level,
                    risk_score=risk_score,
                    files_changed=files_changed,
                    detections=detections,
                    last_event=last_event,
                    uptime=uptime_str,
                    model_status=model_status,
                    monitoring_path=monitoring_label,
                )

                time.sleep(0.2)

        except KeyboardInterrupt:
            print("\n")
            console.print_banner("Stopping monitoring...", "info")
        finally:
            worker.stop()
            display.stop()
            console.print_banner("Monitoring stopped.", "success")

        return 0

    else:
        # Bounded monitoring - simple output
        print()
        console.print_banner(f"Running {arguments.samples} monitoring samples across {len(monitoringPaths)} path(s)...", "info")

        controller = DetectionController(
            monitoredPaths=monitoringPaths,
            databasePath=databasePath,
            modelPath=modelPath if modelPath.is_file() else None,
        )
        if getattr(arguments, "hot_reload", False):
            controller.enableHotReloader()

        try:
            controller.run(arguments.interval, arguments.samples)
            console.print_banner("Monitoring session completed", "success")
            return 0
        except Exception as error:
            console.print_banner(f"Monitoring failed: {error}", "error")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
