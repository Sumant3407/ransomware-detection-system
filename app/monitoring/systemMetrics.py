"""Low-cost host metrics used by the feature window."""

from dataclasses import dataclass

import psutil


@dataclass
class SystemMetrics:
    cpuUsage: float
    memoryUsage: float
    networkBytes: int
    networkConnectionCount: int


class SystemMetricsSource:
    def __init__(self):
        self.previousNetworkBytes: int | None = None

    def collect(self) -> SystemMetrics:
        cpuUsage = psutil.cpu_percent(interval=None)
        memoryUsage = psutil.virtual_memory().percent
        networkStats = psutil.net_io_counters()
        totalNetworkBytes = networkStats.bytes_sent + networkStats.bytes_recv
        networkBytes = 0 if self.previousNetworkBytes is None else max(
            0, totalNetworkBytes - self.previousNetworkBytes
        )
        self.previousNetworkBytes = totalNetworkBytes
        try:
            networkConnectionCount = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, psutil.Error):
            networkConnectionCount = 0
        return SystemMetrics(
            cpuUsage=round(cpuUsage, 2),
            memoryUsage=round(memoryUsage, 2),
            networkBytes=networkBytes,
            networkConnectionCount=networkConnectionCount,
        )
