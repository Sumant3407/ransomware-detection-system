"""Interactive command-line interface for ransomware detection system."""

import json
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from app.config.configuration import (
    getDataDirectory,
    getProjectRoot,
    loadConfiguration,
    resolveMonitoringPath,
)
from app.runtime.controller import DetectionController
from app.runtime.genericWorker import MonitoringWorker
from app.ui.console import (
    ConsoleDisplay,
    LiveMonitorDisplay,
    print_menu,
    print_status_table,
)
from app.detection.predictor import ModelPredictor, ModelValidationError


class InteractiveCLI:
    """Interactive command-line interface."""

    def __init__(self):
        """Initialize interactive CLI."""
        self.console = ConsoleDisplay()
        self.configuration = loadConfiguration()
        self.databasePath = getDataDirectory() / "database" / "detector.sqlite3"
        self.monitoringPath = resolveMonitoringPath(
            self.configuration["monitoring"]["paths"][0]
        )
        self.modelPath = self._get_model_path()
        self.worker: Optional[MonitoringWorker] = None
        self.monitoring_active = False
        self.session_start_time: Optional[datetime] = None

    def _get_model_path(self) -> Path:
        """Get configured model path."""
        model_path = Path(self.configuration["model"].get("path", ""))
        if not model_path.is_absolute():
            model_path = getProjectRoot() / model_path
        return model_path

    def run(self) -> int:
        """Run interactive menu loop."""
        while True:
            try:
                choice = self.show_main_menu()
                if choice is None:
                    break

                if choice == "1":
                    self.start_monitoring()
                elif choice == "2":
                    self.stop_monitoring()
                elif choice == "3":
                    self.view_status()
                elif choice == "4":
                    self.scan_now()
                elif choice == "5":
                    self.view_history()
                elif choice == "6":
                    self.configuration_menu()
                elif choice == "7":
                    self.view_model_info()
                elif choice == "8":
                    break

            except KeyboardInterrupt:
                print("\n")
                if self.monitoring_active:
                    self.console.print_banner(
                        "Monitoring is still running. Stop it first or press Ctrl+C again to force quit.",
                        "warning"
                    )
                else:
                    break
            except Exception as error:
                self.console.print_banner(f"Error: {error}", "error")
                input("Press Enter to continue...")

        if self.monitoring_active:
            self.stop_monitoring()

        self.console.print_banner("Goodbye!", "info")
        return 0

    def show_main_menu(self) -> Optional[str]:
        """Display main menu and get user choice."""
        self.console.clear_screen()

        # Show header
        print(self.console.BOLD + self.console.CYAN)
        print("╔" + "═" * 58 + "╗")
        print("║" + "  RANSOMWARE DETECTION SYSTEM  ".center(58) + "║")
        print("╚" + "═" * 58 + "╝")
        print(self.console.RESET)

        # Show current status
        status_color = self.console.GREEN if self.monitoring_active else self.console.RED
        status_text = "● MONITORING ACTIVE" if self.monitoring_active else "● STOPPED"
        print(f"\nStatus: {status_color}{self.console.BOLD}{status_text}{self.console.RESET}")

        if self.monitoring_active and self.session_start_time:
            uptime = datetime.now() - self.session_start_time
            print(f"Uptime: {self.console.DIM}{self._format_uptime(uptime)}{self.console.RESET}")

        print()

        # Menu options
        print_menu("MAIN MENU", [
            ("1", "Start Monitoring" if not self.monitoring_active else "View Live Monitoring"),
            ("2", "Stop Monitoring"),
            ("3", "View Status"),
            ("4", "Scan Now"),
            ("5", "View Detection History"),
            ("6", "Configuration"),
            ("7", "Model Information"),
            ("8", "Exit"),
        ])

        choice = input(f"{self.console.CYAN}Select option: {self.console.RESET}").strip()
        return choice if choice else None

    def start_monitoring(self) -> None:
        """Start background monitoring with live display."""
        if self.monitoring_active:
            self._show_live_monitoring()
            return

        self.console.print_banner("Starting monitoring...", "info")

        # Validate model
        model_valid = self._is_model_valid(self.modelPath)
        if not model_valid:
            print(f"{self.console.YELLOW}Warning: No valid model found. Detection will use rule-based analysis only.{self.console.RESET}")
            proceed = input("Continue? (y/n): ").strip().lower()
            if proceed != 'y':
                return

        # Start worker
        self.session_start_time = datetime.now()
        self.worker = MonitoringWorker(
            self.monitoringPath,
            self.databasePath,
            self.modelPath if model_valid else None,
            intervalSeconds=float(self.configuration["monitoring"].get("intervalSeconds", 1)),
            onError=self._on_monitoring_error,
            onFinished=self._on_monitoring_finished,
        )

        try:
            self.worker.start()
            self.monitoring_active = True
            self.console.print_banner("Monitoring started successfully!", "success")
            time.sleep(1)
            self._show_live_monitoring()
        except Exception as error:
            self.console.print_banner(f"Failed to start monitoring: {error}", "error")
            input("Press Enter to continue...")

    def _show_live_monitoring(self) -> None:
        """Show live monitoring display."""
        display = LiveMonitorDisplay()
        display.start()

        try:
            while self.monitoring_active and self.worker and self.worker.is_running():
                # Get current stats from database
                stats = self._get_monitoring_stats()

                uptime = datetime.now() - self.session_start_time if self.session_start_time else timedelta(0)

                model_status = "Active" if self._is_model_valid(self.modelPath) else "No model (rule-based only)"

                display.update(
                    protected=self.monitoring_active,
                    threat_level=stats["threat_level"],
                    risk_score=stats["risk_score"],
                    files_changed=stats["files_changed"],
                    detections=stats["detections"],
                    last_event=stats["last_event"],
                    uptime=self._format_uptime(uptime),
                    model_status=model_status,
                    monitoring_path=str(self.monitoringPath),
                )

                time.sleep(0.2)  # Refresh 5 times per second

        except KeyboardInterrupt:
            pass
        finally:
            display.stop()
            print("\n")

    def stop_monitoring(self) -> None:
        """Stop monitoring."""
        if not self.monitoring_active:
            self.console.print_banner("Monitoring is not running.", "info")
            input("Press Enter to continue...")
            return

        self.console.print_banner("Stopping monitoring...", "info")

        if self.worker:
            self.worker.stop()

        self.monitoring_active = False
        self.session_start_time = None

        self.console.print_banner("Monitoring stopped.", "success")
        time.sleep(1)

    def view_status(self) -> None:
        """Display detailed status information."""
        self.console.clear_screen()
        print(self.console.format_header("SYSTEM STATUS"))

        # Protection status
        print(f"{self.console.BOLD}Protection Status:{self.console.RESET}")
        print(self.console.format_status_line(
            "  State",
            "ACTIVE" if self.monitoring_active else "STOPPED",
            self.console.GREEN if self.monitoring_active else self.console.RED
        ))

        if self.monitoring_active and self.session_start_time:
            uptime = datetime.now() - self.session_start_time
            print(self.console.format_status_line("  Uptime", self._format_uptime(uptime)))

        print()

        # Configuration
        print(f"{self.console.BOLD}Configuration:{self.console.RESET}")
        print(self.console.format_status_line("  Monitoring Path", str(self.monitoringPath)))
        print(self.console.format_status_line(
            "  Interval",
            f"{self.configuration['monitoring'].get('intervalSeconds', 1)}s"
        ))
        print(self.console.format_status_line(
            "  Sensitivity",
            self.configuration["monitoring"]["sensitivity"]
        ))
        print()

        # Model status
        print(f"{self.console.BOLD}Model Status:{self.console.RESET}")
        if self._is_model_valid(self.modelPath):
            print(self.console.format_status_line(
                "  Status",
                "Valid",
                self.console.GREEN
            ))
            print(self.console.format_status_line("  Path", str(self.modelPath)))
        else:
            print(self.console.format_status_line(
                "  Status",
                "No valid model (using rule-based detection)",
                self.console.YELLOW
            ))
        print()

        # Database stats
        stats = self._get_monitoring_stats()
        print(f"{self.console.BOLD}Session Statistics:{self.console.RESET}")
        print(self.console.format_status_line("  Files Changed", str(stats["files_changed"])))
        print(self.console.format_status_line(
            "  Detections",
            str(stats["detections"]),
            self.console.YELLOW if stats["detections"] > 0 else self.console.GREEN
        ))
        print(self.console.format_status_line(
            "  Current Threat Level",
            stats["threat_level"].upper(),
            self.console.get_threat_color(stats["threat_level"])
        ))
        print()

        input(f"{self.console.DIM}Press Enter to continue...{self.console.RESET}")

    def scan_now(self) -> None:
        """Perform a one-time scan."""
        self.console.print_banner("Running scan...", "info")

        try:
            controller = DetectionController(
                self.monitoringPath,
                self.databasePath,
                self.modelPath if self._is_model_valid(self.modelPath) else None,
            )

            try:
                decision = controller.collectOnce()
            finally:
                controller.close()

            print(f"\n{self.console.BOLD}Scan Results:{self.console.RESET}\n")
            print(self.console.format_status_line(
                "Threat Level",
                decision.level.value.upper(),
                self.console.get_threat_color(decision.level.value)
            ))
            print(self.console.format_status_line("Risk Score", f"{decision.score:.4f}"))
            print(self.console.format_status_line("Classification", decision.classification))

            if decision.level.value in ("high", "critical"):
                self.console.print_banner(
                    "RANSOMWARE-LIKE ACTIVITY DETECTED!",
                    "critical"
                )
            elif decision.level.value == "medium":
                self.console.print_banner("Suspicious activity detected", "warning")
            else:
                self.console.print_banner("No threats detected", "success")

        except Exception as error:
            self.console.print_banner(f"Scan failed: {error}", "error")

        print()
        input(f"{self.console.DIM}Press Enter to continue...{self.console.RESET}")

    def view_history(self) -> None:
        """View detection history."""
        self.console.clear_screen()
        print(self.console.format_header("DETECTION HISTORY"))

        connection = sqlite3.connect(self.databasePath)
        try:
            rows = connection.execute(
                "SELECT occurredAt, classification, riskScore, actionTaken "
                "FROM detections ORDER BY detectionId DESC LIMIT 50"
            ).fetchall()
        finally:
            connection.close()

        if not rows:
            print(f"{self.console.DIM}No detections recorded.{self.console.RESET}\n")
        else:
            print_status_table(
                ["Timestamp", "Classification", "Risk Score", "Action"],
                [[row[0], row[1], f"{float(row[2]):.4f}", row[3]] for row in rows]
            )

        print(f"{self.console.DIM}Showing up to 50 most recent detections{self.console.RESET}")
        input(f"\n{self.console.DIM}Press Enter to continue...{self.console.RESET}")

    def configuration_menu(self) -> None:
        """Configuration submenu."""
        while True:
            self.console.clear_screen()
            print_menu("CONFIGURATION", [
                ("1", "Change Monitoring Path"),
                ("2", "Change Monitoring Interval"),
                ("3", "Change Detection Sensitivity"),
                ("4", "Select Model"),
                ("5", "View Current Configuration"),
                ("6", "Back to Main Menu"),
            ])

            choice = input(f"{self.console.CYAN}Select option: {self.console.RESET}").strip()

            if choice == "1":
                self._config_change_path()
            elif choice == "2":
                self._config_change_interval()
            elif choice == "3":
                self._config_change_sensitivity()
            elif choice == "4":
                self._config_select_model()
            elif choice == "5":
                self._config_view()
            elif choice == "6":
                break

    def _config_change_path(self) -> None:
        """Change monitoring path."""
        print(f"\n{self.console.BOLD}Current path:{self.console.RESET} {self.monitoringPath}")
        new_path = input("Enter new path (or press Enter to cancel): ").strip()

        if not new_path:
            return

        try:
            resolved = resolveMonitoringPath(new_path)
            self.monitoringPath = resolved
            self.configuration["monitoring"]["paths"] = [str(resolved)]
            self._save_configuration()
            self.console.print_banner(f"Monitoring path updated to: {resolved}", "success")
        except Exception as error:
            self.console.print_banner(f"Invalid path: {error}", "error")

        time.sleep(2)

    def _config_change_interval(self) -> None:
        """Change monitoring interval."""
        current = self.configuration["monitoring"].get("intervalSeconds", 1)
        print(f"\n{self.console.BOLD}Current interval:{self.console.RESET} {current}s")
        new_interval = input("Enter new interval in seconds (1-60, or press Enter to cancel): ").strip()

        if not new_interval:
            return

        try:
            interval = float(new_interval)
            if interval < 1 or interval > 60:
                raise ValueError("Interval must be between 1 and 60 seconds")

            self.configuration["monitoring"]["intervalSeconds"] = interval
            self._save_configuration()
            self.console.print_banner(f"Monitoring interval updated to: {interval}s", "success")
        except ValueError as error:
            self.console.print_banner(f"Invalid interval: {error}", "error")

        time.sleep(2)

    def _config_change_sensitivity(self) -> None:
        """Change detection sensitivity."""
        print(f"\n{self.console.BOLD}Available sensitivity levels:{self.console.RESET}")
        print("  1. Conservative (fewer false positives)")
        print("  2. Balanced (recommended)")
        print("  3. Aggressive (more sensitive)")
        print()
        current = self.configuration["monitoring"]["sensitivity"]
        print(f"{self.console.BOLD}Current:{self.console.RESET} {current}")
        print()

        choice = input("Select sensitivity (1-3, or press Enter to cancel): ").strip()

        sensitivity_map = {
            "1": "conservative",
            "2": "balanced",
            "3": "aggressive",
        }

        if choice in sensitivity_map:
            new_sensitivity = sensitivity_map[choice]
            self.configuration["monitoring"]["sensitivity"] = new_sensitivity
            self._save_configuration()
            self.console.print_banner(f"Sensitivity updated to: {new_sensitivity}", "success")
            time.sleep(2)

    def _config_select_model(self) -> None:
        """Select model file."""
        print(f"\n{self.console.BOLD}Searching for model files...{self.console.RESET}")

        model_root = getDataDirectory() / "models"
        candidates = []

        if model_root.exists():
            candidates = list(model_root.rglob("*.joblib"))

        if not candidates:
            self.console.print_banner("No model files found in data/models/", "warning")
            input("Press Enter to continue...")
            return

        print(f"\n{self.console.BOLD}Available models:{self.console.RESET}")
        for i, path in enumerate(candidates, 1):
            valid = "✓" if self._is_model_valid(path) else "✗"
            print(f"  {i}. {valid} {path}")

        print()
        choice = input("Select model (number, or press Enter to cancel): ").strip()

        try:
            index = int(choice) - 1
            if 0 <= index < len(candidates):
                selected = candidates[index]
                self.modelPath = selected
                self.configuration["model"]["path"] = str(selected)
                self._save_configuration()
                self.console.print_banner(f"Model updated to: {selected.name}", "success")
            else:
                raise ValueError("Invalid selection")
        except (ValueError, IndexError) as error:
            if choice:  # Only show error if user entered something
                self.console.print_banner(f"Invalid selection: {error}", "error")

        time.sleep(2)

    def _config_view(self) -> None:
        """View current configuration."""
        self.console.clear_screen()
        print(self.console.format_header("CURRENT CONFIGURATION"))

        config_json = json.dumps(self.configuration, indent=2)
        print(self.console.DIM + config_json + self.console.RESET)
        print()

        input(f"{self.console.DIM}Press Enter to continue...{self.console.RESET}")

    def _save_configuration(self) -> None:
        """Save configuration to settings.json."""
        settings_path = getDataDirectory() / "settings.json"
        settings_path.write_text(
            json.dumps(self.configuration, indent=2),
            encoding="utf-8"
        )

    def view_model_info(self) -> None:
        """View detailed model information."""
        self.console.clear_screen()
        print(self.console.format_header("MODEL INFORMATION"))

        print(self.console.format_status_line("Model Path", str(self.modelPath)))

        if not self.modelPath.is_file():
            self.console.print_banner("Model file not found", "error")
        else:
            try:
                predictor = ModelPredictor(self.modelPath)
                print(self.console.format_status_line(
                    "Status",
                    "Valid",
                    self.console.GREEN
                ))
                print(self.console.format_status_line(
                    "File Size",
                    f"{self.modelPath.stat().st_size / 1024:.2f} KB"
                ))

                # Try to read metadata
                metadata_path = self.modelPath.parent / f"{self.modelPath.stem}.metadata.json"
                if metadata_path.exists():
                    try:
                        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                        print(f"\n{self.console.BOLD}Metadata:{self.console.RESET}")
                        for key, value in metadata.items():
                            if isinstance(value, dict):
                                print(f"  {key}:")
                                for k, v in value.items():
                                    print(f"    {k}: {v}")
                            else:
                                print(f"  {key}: {value}")
                    except Exception:
                        pass

            except ModelValidationError as error:
                print(self.console.format_status_line(
                    "Status",
                    f"Invalid: {error}",
                    self.console.RED
                ))

        print()
        input(f"{self.console.DIM}Press Enter to continue...{self.console.RESET}")

    def _get_monitoring_stats(self) -> dict:
        """Get current monitoring statistics from database."""
        connection = sqlite3.connect(self.databasePath)
        try:
            # Get file event count for current session
            files_changed = connection.execute(
                """
                SELECT COUNT(*)
                FROM fileEvents
                WHERE sessionId = (
                    SELECT sessionId
                    FROM sessions
                    ORDER BY sessionId DESC
                    LIMIT 1
                )
                """
            ).fetchone()[0]

            # Get detection count
            detections = connection.execute(
                "SELECT COUNT(*) FROM detections WHERE classification != 'benign'"
            ).fetchone()[0]

            # Get latest detection
            latest = connection.execute(
                "SELECT occurredAt, classification, riskScore "
                "FROM detections ORDER BY detectionId DESC LIMIT 1"
            ).fetchone()

            # Get last event
            last_event_row = connection.execute(
                "SELECT action, occurredAt FROM fileEvents "
                "ORDER BY eventId DESC LIMIT 1"
            ).fetchone()

            threat_level = "low"
            risk_score = 0.0

            if latest:
                risk_score = float(latest[2])
                if risk_score >= 0.85:
                    threat_level = "critical"
                elif risk_score >= 0.65:
                    threat_level = "high"
                elif risk_score >= 0.40:
                    threat_level = "medium"

            last_event = ""
            if last_event_row:
                last_event = f"{last_event_row[0]} at {last_event_row[1]}"

            return {
                "files_changed": files_changed,
                "detections": detections,
                "threat_level": threat_level,
                "risk_score": risk_score,
                "last_event": last_event,
            }

        finally:
            connection.close()

    def _is_model_valid(self, path: Path) -> bool:
        """Check if model is valid."""
        if not path.is_file():
            return False
        try:
            ModelPredictor(path)
            return True
        except ModelValidationError:
            return False

    def _format_uptime(self, delta: timedelta) -> str:
        """Format uptime timedelta as string."""
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def _on_monitoring_error(self, error: str) -> None:
        """Handle monitoring error callback."""
        self.monitoring_active = False
        print(f"\n{self.console.RED}Monitoring error: {error}{self.console.RESET}")

    def _on_monitoring_finished(self) -> None:
        """Handle monitoring finished callback."""
        pass  # Already handled by stop_monitoring()


def run_interactive() -> int:
    """Run interactive CLI interface."""
    cli = InteractiveCLI()
    return cli.run()
