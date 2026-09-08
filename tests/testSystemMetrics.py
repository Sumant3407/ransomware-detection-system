import unittest
from unittest.mock import patch

from app.monitoring.systemMetrics import SystemMetricsSource


class SystemMetricsTests(unittest.TestCase):
    @patch("app.monitoring.systemMetrics.psutil.net_connections", return_value=[])
    @patch("app.monitoring.systemMetrics.psutil.net_io_counters")
    @patch("app.monitoring.systemMetrics.psutil.virtual_memory")
    @patch("app.monitoring.systemMetrics.psutil.cpu_percent", return_value=12.5)
    def testNetworkDeltaAndSystemValues(self, cpuMock, memoryMock, networkMock, connectionsMock):
        memoryMock.return_value.percent = 42.0
        networkMock.side_effect = [
            type("Network", (), {"bytes_sent": 100, "bytes_recv": 50})(),
            type("Network", (), {"bytes_sent": 140, "bytes_recv": 80})(),
        ]
        source = SystemMetricsSource()
        firstMetrics = source.collect()
        secondMetrics = source.collect()
        self.assertEqual(firstMetrics.networkBytes, 0)
        self.assertEqual(secondMetrics.networkBytes, 70)
        self.assertEqual(secondMetrics.cpuUsage, 12.5)
        self.assertEqual(secondMetrics.memoryUsage, 42.0)


if __name__ == "__main__":
    unittest.main()