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
  python -m app.main --scan                 Perform one-time scan
        """
    )
    parser.add_argument("--status", action="store_true", help="Show detailed protection status")
    parser.add_argument("--version", action="store_true", help="Show application version")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive menu interface")
    parser.add_argument("--monitor", action="store_true", help="Run headless monitoring session")
    parser.add_argument("--samples", type=int, default=None, help="Number of monitoring samples (default: unlimited)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between monitoring samples")
    parser.add_argument("--scan", action="store_true", help="Perform a one-time scan")
    parser.add_argument("--history", action="store_true", help="Show detection history")
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
        return showDetailedStatus(configuration, databasePath)

    # Detection history
    if arguments.history:
        return showHistory(databasePath)

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

    # One-time scan
    if arguments.scan:
        return performScan(configuration, databasePath)

    # Headless monitoring
    if arguments.monitor:
        return runHeadlessMonitoring(configuration, databasePath, arguments)

    # Default: show help or run interactive mode
    print(f"Ransomware Detection System v{applicationVersion}")
    print("Use --help to see available options")
    print("Use --interactive to launch the menu interface")
    print("Use --status to view current status")
    return 0


def showDetailedStatus(configuration: dict, databasePath: Path) -> int:
    """Show detailed system status."""
    import sqlite3
    from app.ui.console import ConsoleDisplay, print_status_table
    from app.detection.predictor import ModelPredictor, ModelValidationError

    console = ConsoleDisplay()
    print()
    print(console.format_header("RANSOMWARE DETECTION SYSTEM - STATUS"))

    # Configuration
    print(f"{console.BOLD}Configuration:{console.RESET}")
    monitoringPath = resolveMonitoringPath(configuration["monitoring"]["paths"][0])
    print(console.format_status_line("  Monitoring Path", str(monitoringPath)))
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
    modelPath = Path(configuration["model"].get("path", ""))
    if not modelPath.is_absolute():
        modelPath = getProjectRoot() / modelPath

    if modelPath.is_file():
        try:
            ModelPredictor(modelPath)
            print(console.format_status_line("  Status", "Valid", console.GREEN))
            print(console.format_status_line("  Path", str(modelPath)))
        except ModelValidationError as error:
            print(console.format_status_line("  Status", f"Invalid: {error}", console.RED))
    else:
        print(console.format_status_line("  Status", "No model found", console.YELLOW))
    print()

    # Database statistics
    print(f"{console.BOLD}Database Statistics:{console.RESET}")
    try:
        connection = sqlite3.connect(databasePath)
        total_events = connection.execute("SELECT COUNT(*) FROM fileEvents").fetchone()[0]
        total_detections = connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        total_sessions = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        connection.close()

        print(console.format_status_line("  Total Sessions", str(total_sessions)))
        print(console.format_status_line("  Total File Events", str(total_events)))
        print(console.format_status_line("  Total Detections", str(total_detections)))
    except Exception as error:
        print(console.format_status_line("  Error", str(error), console.RED))

    print()
    return 0


def showHistory(databasePath: Path) -> int:
    """Show detection history."""
    import sqlite3
    from app.ui.console import ConsoleDisplay, print_status_table

    console = ConsoleDisplay()
    print()
    print(console.format_header("DETECTION HISTORY"))

    try:
        connection = sqlite3.connect(databasePath)
        rows = connection.execute(
            "SELECT occurredAt, classification, riskScore, actionTaken "
            "FROM detections ORDER BY detectionId DESC LIMIT 50"
        ).fetchall()
        connection.close()

        if not rows:
            print(f"{console.DIM}No detections recorded.{console.RESET}\n")
        else:
            print_status_table(
                ["Timestamp", "Classification", "Risk Score", "Action"],
                [[row[0], row[1], f"{float(row[2]):.4f}", row[3]] for row in rows]
            )
            print(f"{console.DIM}Showing up to 50 most recent detections{console.RESET}")

        print()
        return 0
    except Exception as error:
        print(f"Error reading history: {error}")
        return 1


def performScan(configuration: dict, databasePath: Path) -> int:
    """Perform one-time scan."""
    from app.ui.console import ConsoleDisplay

    console = ConsoleDisplay()
    print()
    console.print_banner("Performing scan...", "info")

    try:
        monitoringPath = resolveMonitoringPath(configuration["monitoring"]["paths"][0])
        modelPath = Path(configuration["model"].get("path", ""))
        if not modelPath.is_absolute():
            modelPath = getProjectRoot() / modelPath

        controller = DetectionController(
            monitoringPath,
            databasePath,
            modelPath if modelPath.is_file() else None
        )

        try:
            decision = controller.collectOnce()
        finally:
            controller.close()

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
        console.print_banner(f"Scan failed: {error}", "error")
        return 1


def runHeadlessMonitoring(configuration: dict, databasePath: Path, arguments: argparse.Namespace) -> int:
    """Run headless monitoring session."""
    from app.ui.console import ConsoleDisplay, LiveMonitorDisplay
    from app.runtime.genericWorker import MonitoringWorker
    from datetime import datetime, timedelta
    import time

    console = ConsoleDisplay()

    monitoringPath = resolveMonitoringPath(configuration["monitoring"]["paths"][0])
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
            monitoringPath,
            databasePath,
            modelPath if modelPath.is_file() else None,
            intervalSeconds=arguments.interval,
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

                display.update(
                    protected=True,
                    threat_level=threat_level,
                    risk_score=risk_score,
                    files_changed=files_changed,
                    detections=detections,
                    last_event=last_event,
                    uptime=uptime_str,
                    model_status=model_status,
                    monitoring_path=str(monitoringPath),
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
        console.print_banner(f"Running {arguments.samples} monitoring samples...", "info")

        controller = DetectionController(
            monitoringPath,
            databasePath,
            modelPath if modelPath.is_file() else None
        )

        try:
            controller.run(arguments.interval, arguments.samples)
            console.print_banner("Monitoring session completed", "success")
            return 0
        except Exception as error:
            console.print_banner(f"Monitoring failed: {error}", "error")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
