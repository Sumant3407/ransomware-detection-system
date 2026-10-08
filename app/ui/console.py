"""Console display utilities for real-time monitoring visualization."""

import sys
import shutil
from datetime import datetime
from typing import Optional


class ConsoleDisplay:
    """Manages live-updating console display with ANSI escape codes."""

    # ANSI escape codes for colors and formatting
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Background colors
    BG_RED = "\033[101m"
    BG_GREEN = "\033[102m"
    BG_YELLOW = "\033[103m"

    # Cursor control
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"
    CLEAR_SCREEN = "\033[2J\033[H"
    CLEAR_LINE = "\033[2K"

    def __init__(self):
        """Initialize console display."""
        self.width, self.height = shutil.get_terminal_size(fallback=(80, 24))
        self.lines_printed = 0

    def clear_screen(self) -> None:
        """Clear entire screen and move cursor to top."""
        sys.stdout.write(self.CLEAR_SCREEN)
        sys.stdout.flush()

    def hide_cursor(self) -> None:
        """Hide terminal cursor."""
        sys.stdout.write(self.HIDE_CURSOR)
        sys.stdout.flush()

    def show_cursor(self) -> None:
        """Show terminal cursor."""
        sys.stdout.write(self.SHOW_CURSOR)
        sys.stdout.flush()

    def move_up(self, lines: int) -> None:
        """Move cursor up N lines."""
        sys.stdout.write(f"\033[{lines}A")
        sys.stdout.flush()

    def clear_previous(self, lines: int) -> None:
        """Clear previous N lines."""
        for _ in range(lines):
            sys.stdout.write("\033[1A\033[2K")
        sys.stdout.flush()

    def get_threat_color(self, level: str) -> str:
        """Get color code for threat level."""
        colors = {
            "low": self.GREEN,
            "medium": self.YELLOW,
            "high": self.RED,
            "critical": self.RED + self.BOLD,
        }
        return colors.get(level.lower(), self.WHITE)

    def format_header(self, text: str, width: Optional[int] = None) -> str:
        """Format a section header."""
        w = width or self.width
        return f"{self.BOLD}{self.CYAN}{text}{self.RESET}\n{'=' * w}\n"

    def format_status_line(self, label: str, value: str, color: str = "") -> str:
        """Format a status line with label and value."""
        reset = self.RESET if color else ""
        return f"{self.DIM}{label}:{self.RESET} {color}{value}{reset}\n"

    def format_box(self, title: str, content: str, color: str = CYAN) -> str:
        """Format content in a box."""
        width = self.width - 4
        lines = [
            f"{color}+{'-' * (width - 2)}+{self.RESET}",
            f"{color}|{self.RESET} {self.BOLD}{title}{self.RESET}{' ' * (width - len(title) - 3)}{color}|{self.RESET}",
            f"{color}+{'-' * (width - 2)}+{self.RESET}",
        ]

        for line in content.split('\n'):
            padding = width - len(line) - 3
            lines.append(f"{color}|{self.RESET} {line}{' ' * padding}{color}|{self.RESET}")

        lines.append(f"{color}+{'-' * (width - 2)}+{self.RESET}")
        return '\n'.join(lines) + '\n'

    def print_banner(self, text: str, style: str = "info") -> None:
        """Print a banner message."""
        styles = {
            "info": (self.BLUE, "[i]"),
            "success": (self.GREEN, "[OK]"),
            "warning": (self.YELLOW, "[!]"),
            "error": (self.RED, "[X]"),
            "critical": (self.BG_RED + self.WHITE, "[CRITICAL]"),
        }
        color, icon = styles.get(style, (self.WHITE, "*"))
        print(f"\n{color}{self.BOLD} {icon} {text} {self.RESET}\n")


class LiveMonitorDisplay:
    """Live-updating monitoring display."""

    def __init__(self):
        """Initialize live display."""
        self.console = ConsoleDisplay()
        self.last_lines = 0

    def start(self) -> None:
        """Start live display mode."""
        self.console.hide_cursor()
        self.console.clear_screen()

    def stop(self) -> None:
        """Stop live display mode."""
        self.console.show_cursor()

    def update(
        self,
        protected: bool,
        threat_level: str,
        risk_score: float,
        files_changed: int,
        detections: int,
        last_event: str,
        uptime: str,
        model_status: str,
        monitoring_path: str,
    ) -> None:
        """
        Update the live display with current stats.

        Args:
            protected: Whether monitoring is active
            threat_level: Current threat level (low/medium/high/critical)
            risk_score: Risk score 0.0-1.0
            files_changed: Number of files changed this session
            detections: Number of detections
            last_event: Description of last file event
            uptime: Monitoring uptime string
            model_status: Model status message
            monitoring_path: Path being monitored
        """
        # Clear previous output
        if self.last_lines > 0:
            self.console.clear_previous(self.last_lines)

        output = []
        c = self.console

        # Header
        output.append(f"{c.BOLD}{c.CYAN}{'=' * c.width}{c.RESET}")
        output.append(f"{c.BOLD}{c.CYAN}RANSOMWARE DETECTION SYSTEM - LIVE MONITORING{c.RESET}".center(c.width + len(c.BOLD) + len(c.CYAN) + len(c.RESET)))
        output.append(f"{c.CYAN}{'=' * c.width}{c.RESET}")
        output.append("")

        # Status line
        protection_color = c.GREEN if protected else c.RED
        protection_text = "[*] PROTECTED" if protected else "[!] STOPPED"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        output.append(f"{protection_color}{c.BOLD}{protection_text}{c.RESET}  |  {c.DIM}{timestamp}{c.RESET}")
        output.append("")

        # Threat alert banner
        if threat_level in ("high", "critical"):
            banner_color = c.BG_RED + c.WHITE
            output.append(f"{banner_color}{c.BOLD} [!] RANSOMWARE-LIKE ACTIVITY DETECTED - RISK {risk_score:.2f} [!] {c.RESET}")
            output.append("")
        elif threat_level == "medium":
            banner_color = c.BG_YELLOW + c.WHITE
            output.append(f"{banner_color}{c.BOLD} [!] SUSPICIOUS FILE ACTIVITY - RISK {risk_score:.2f} [!] {c.RESET}")
            output.append("")

        # Main metrics
        threat_color = c.get_threat_color(threat_level)
        output.append(f"{c.BOLD}STATUS OVERVIEW{c.RESET}")
        output.append(f"{'-' * c.width}")
        output.append(f"  Threat Level:     {threat_color}{c.BOLD}{threat_level.upper()}{c.RESET}")
        output.append(f"  Risk Score:       {threat_color}{risk_score:.4f}{c.RESET}")
        output.append(f"  Files Changed:    {c.WHITE}{files_changed}{c.RESET}")
        output.append(f"  Detections:       {c.YELLOW if detections > 0 else c.GREEN}{detections}{c.RESET}")
        output.append(f"  Uptime:           {c.DIM}{uptime}{c.RESET}")
        output.append("")

        # Recent activity
        output.append(f"{c.BOLD}RECENT ACTIVITY{c.RESET}")
        output.append(f"{'-' * c.width}")
        if last_event:
            output.append(f"  {last_event}")
        else:
            output.append(f"  {c.DIM}No recent file activity{c.RESET}")
        output.append("")

        # System info
        output.append(f"{c.BOLD}SYSTEM INFORMATION{c.RESET}")
        output.append(f"{'-' * c.width}")
        output.append(f"  Monitoring Path:  {c.DIM}{monitoring_path}{c.RESET}")
        output.append(f"  Model Status:     {c.DIM}{model_status}{c.RESET}")
        output.append("")

        # Footer
        output.append(f"{c.DIM}Press Ctrl+C to stop monitoring{c.RESET}")

        # Print all lines
        display_text = '\n'.join(output)
        print(display_text, end='', flush=True)

        # Track number of lines for next update
        self.last_lines = len(output)


def print_menu(title: str, options: list[tuple[str, str]]) -> None:
    """
    Print an interactive menu.

    Args:
        title: Menu title
        options: List of (key, description) tuples
    """
    console = ConsoleDisplay()

    print()
    print(console.format_header(title))

    for key, description in options:
        print(f"  {console.CYAN}{console.BOLD}[{key}]{console.RESET}  {description}")

    print()


def print_status_table(headers: list[str], rows: list[list[str]]) -> None:
    """
    Print a formatted table.

    Args:
        headers: Column headers
        rows: Table rows (list of lists)
    """
    console = ConsoleDisplay()

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Print header
    header_line = " | ".join(
        f"{console.BOLD}{h:<{w}}{console.RESET}"
        for h, w in zip(headers, col_widths)
    )
    print(header_line)
    print("-" * (sum(col_widths) + 3 * (len(headers) - 1)))

    # Print rows
    for row in rows:
        row_line = " | ".join(
            f"{str(cell):<{w}}" for cell, w in zip(row, col_widths)
        )
        print(row_line)

    print()
