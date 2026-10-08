"""Low-cost host metrics used by the feature window."""

import logging
from dataclasses import dataclass

import psutil

logger = logging.getLogger(__name__)


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
        cpuUsage = 0.0
        memoryUsage = 0.0
        networkBytes = 0
        networkConnectionCount = 0

        try:
            val = psutil.cpu_percent(interval=None)
            if val is not None:
                cpuUsage = float(val)
        except BaseException as error:
            logger.debug(f"Error reading CPU percent: {error}")

        try:
            mem = psutil.virtual_memory()
            if mem is not None:
                memoryUsage = float(mem.percent)
        except BaseException as error:
            logger.debug(f"Error reading memory: {error}")

        try:
            networkStats = psutil.net_io_counters()
            if networkStats is not None:
                totalNetworkBytes = networkStats.bytes_sent + networkStats.bytes_recv
                networkBytes = 0 if self.previousNetworkBytes is None else max(
                    0, totalNetworkBytes - self.previousNetworkBytes
                )
                self.previousNetworkBytes = totalNetworkBytes
        except BaseException as error:
            logger.debug(f"Error reading net_io_counters: {error}")

        try:
            connections = psutil.net_connections(kind="inet")
            if connections is not None:
                networkConnectionCount = len(connections)
        except BaseException as error:
            logger.debug(f"Unable to read network connections: {error}")

        return SystemMetrics(
            cpuUsage=round(cpuUsage, 2),
            memoryUsage=round(memoryUsage, 2),
            networkBytes=networkBytes,
            networkConnectionCount=networkConnectionCount,
        )
