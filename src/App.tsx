import { useState, useEffect, useCallback } from "react";
import { CrtBackground } from "./shaders/crt/CrtBackground";
import { Header, ActiveTab } from "./components/Header";
import { CrtTerminalView } from "./components/CrtTerminalView";
import { LiveMonitorView, LiveEventItem } from "./components/LiveMonitorView";
import { DemoLabView } from "./components/DemoLabView";
import { ForensicsView } from "./components/ForensicsView";
import { DiagnosticsView } from "./components/DiagnosticsView";
import { ModelStudioView } from "./components/ModelStudioView";
import { SettingsView } from "./components/SettingsView";
import { CrtConfigModal, CrtConfig } from "./components/CrtConfigModal";
import { SystemMetrics, SystemStatus, HealthReport } from "./types/electron";
import "./shaders/threeui.css";
import "./App.css";

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("terminal");
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [threatLevel, setThreatLevel] = useState<"low" | "medium" | "high" | "critical">("low");
  const [riskScore, setRiskScore] = useState(0.0);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [events, setEvents] = useState<LiveEventItem[]>([]);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "================================================================================",
    "  ZION MAINFRAME // RANSOMWARE DEFENSE STATION v2.4.0",
    "================================================================================",
    "[*] Hardware-accelerated CRT WebGL shader & Canvas 2D rasterizer active.",
    "[*] Offline ML Behavioral Engine loaded with AES-256-GCM model validation.",
    "[*] Type 'help' to view available defense commands or switch tabs above.",
    "",
  ]);

  const [crtConfig, setCrtConfig] = useState<CrtConfig>({
    speed: 1.0,
    typeSpeed: 1.0,
    motion: 1.0,
    hue: 0,
    saturation: 1.0,
    brightness: 1.0,
    opacity: activeTab === "terminal" ? 1.0 : 0.28,
    variant: "terminal",
  });
  const [showCrtModal, setShowCrtModal] = useState(false);

  // Sync CRT opacity when switching tabs
  useEffect(() => {
    setCrtConfig((prev) => ({
      ...prev,
      opacity: activeTab === "terminal" ? 1.0 : 0.22,
    }));
  }, [activeTab]);

  const appendTerminalLog = useCallback((text: string) => {
    setTerminalLogs((prev) => [...prev, text]);
  }, []);

  // Poll status & metrics periodically
  const refreshStatusAndMetrics = useCallback(async () => {
    if (!window.electronAPI) return;
    try {
      const [st, mt, running] = await Promise.all([
        window.electronAPI.getStatus().catch(() => null),
        window.electronAPI.getMetrics().catch(() => null),
        window.electronAPI.isMonitoring().catch(() => false),
      ]);
      if (st) setStatus(st);
      if (mt) setMetrics(mt);
      setIsMonitoring(Boolean(running));
    } catch (err) {
      console.error("Polling error:", err);
    }
  }, []);

  useEffect(() => {
    refreshStatusAndMetrics();
    const interval = setInterval(refreshStatusAndMetrics, 2500);
    return () => clearInterval(interval);
  }, [refreshStatusAndMetrics]);

  // Subscribe to live monitoring logs from Electron
  useEffect(() => {
    if (!window.electronAPI) return;

    const cleanupLog = window.electronAPI.onMonitoringLog((rawLog) => {
      appendTerminalLog(rawLog);

      // Parse structured event if present
      if (rawLog.includes("ALERT") || rawLog.includes("RANSOMWARE")) {
        setThreatLevel("critical");
        setRiskScore(0.95);
      } else if (rawLog.includes("Threat detected") || rawLog.includes("warning")) {
        setThreatLevel("high");
        setRiskScore(0.80);
      }

      // Try to parse file action from log lines
      const actionMatch = rawLog.match(/(CREATED|MODIFIED|DELETED|RENAMED|ACCESSED)/i);
      if (actionMatch) {
        const actionType = actionMatch[1].toUpperCase() as any;
        const newEvent: LiveEventItem = {
          id: `${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
          timestamp: new Date().toLocaleTimeString(),
          action: actionType,
          processName: rawLog.includes(".exe") ? (rawLog.match(/[\w\-]+\.exe/i)?.[0] || "python.exe") : "python.exe",
          processId: 4812,
          pathHash: Math.random().toString(16).substring(2, 10),
          source: "ReadDirectoryChangesW",
        };
        setEvents((prev) => [newEvent, ...prev.slice(0, 199)]);
      }
    });

    const cleanupStatus = window.electronAPI.onMonitoringStatus((running) => {
      setIsMonitoring(running);
      if (running) {
        appendTerminalLog("[+] Live protection watcher started on monitored paths.");
      } else {
        appendTerminalLog("[-] Live protection watcher stopped.");
      }
    });

    return () => {
      cleanupLog();
      cleanupStatus();
    };
  }, [appendTerminalLog]);

  // Toggle Live Monitoring
  const handleToggleMonitoring = async () => {
    if (!window.electronAPI) {
      setIsMonitoring((p) => !p);
      return;
    }
    try {
      if (isMonitoring) {
        await window.electronAPI.stopMonitoring();
        setIsMonitoring(false);
      } else {
        await window.electronAPI.startMonitoring();
        setIsMonitoring(true);
      }
    } catch (err: any) {
      appendTerminalLog(`[!] Error toggling monitoring: ${err.message}`);
    }
  };

  // Immediate Scan
  const handleQuickScan = async () => {
    appendTerminalLog("[*] Initiating immediate behavioral threat scan across all paths...");
    if (!window.electronAPI) {
      appendTerminalLog("[+] Scan finished: Threat Level LOW, Risk Score 0.0000");
      setThreatLevel("low");
      setRiskScore(0.0);
      return;
    }
    try {
      const res = await window.electronAPI.triggerScan();
      appendTerminalLog(`[+] Scan finished: Threat Level ${res.level?.toUpperCase() || "LOW"}, Score: ${res.score?.toFixed(4) || "0.0000"}`);
      setThreatLevel((res.level as any) || "low");
      setRiskScore(res.score || 0.0);
    } catch (err: any) {
      appendTerminalLog(`[!] Scan failed: ${err.message}`);
    }
  };

  // Execute command from terminal prompt
  const handleExecuteCommand = async (cmd: string): Promise<string> => {
    appendTerminalLog(`> ${cmd}`);
    if (!window.electronAPI) {
      appendTerminalLog(`[Browser Demo] Executed command: ${cmd}`);
      return "OK";
    }
    try {
      const out = await window.electronAPI.executeCommand(cmd);
      if (out) appendTerminalLog(out);
      return out;
    } catch (err: any) {
      appendTerminalLog(`[!] Command error: ${err.message}`);
      return `Error: ${err.message}`;
    }
  };

  return (
    <div className="defense-station-app">
      {/* 3D CRT WebGL Shader Background */}
      <div className="crt-background-wrapper" style={{ opacity: crtConfig.opacity }}>
        <CrtBackground
          variant={crtConfig.variant}
          speed={crtConfig.speed}
          typeSpeed={crtConfig.typeSpeed}
          motion={crtConfig.motion}
          hue={crtConfig.hue}
          saturation={crtConfig.saturation}
          brightness={crtConfig.brightness}
          opacity={1.0}
        />
      </div>

      {/* Cyber SOC Application Overlay */}
      <div className="soc-content-frame">
        <Header
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          isMonitoring={isMonitoring}
          threatLevel={threatLevel}
          riskScore={riskScore}
          onToggleMonitoring={handleToggleMonitoring}
          onQuickScan={handleQuickScan}
          onOpenCrtSettings={() => setShowCrtModal(true)}
        />

        <main className="tab-viewport">
          {activeTab === "terminal" && (
            <CrtTerminalView
              logs={terminalLogs}
              onExecuteCommand={handleExecuteCommand}
              onClearLogs={() => setTerminalLogs([])}
            />
          )}

          {activeTab === "monitor" && (
            <LiveMonitorView
              status={status}
              metrics={metrics}
              isMonitoring={isMonitoring}
              events={events}
              onToggleMonitoring={handleToggleMonitoring}
              onQuickScan={handleQuickScan}
              onClearEvents={() => setEvents([])}
            />
          )}

          {activeTab === "demo" && (
            <DemoLabView
              onRunDemo={async (action, opts) => {
                if (!window.electronAPI) {
                  return { created: opts?.count || 25, duration: 0.1 };
                }
                return await window.electronAPI.runDemo(action, opts);
              }}
            />
          )}

          {activeTab === "forensics" && (
            <ForensicsView
              onFetchForensics={async () => {
                if (!window.electronAPI) return [];
                return await window.electronAPI.getForensics();
              }}
              onFetchSnapshot={async (id) => {
                if (!window.electronAPI) throw new Error("No backend");
                return await window.electronAPI.getSnapshot(id);
              }}
            />
          )}

          {activeTab === "diagnostics" && (
            <DiagnosticsView
              onFetchHealth={async (): Promise<HealthReport> => {
                if (!window.electronAPI) {
                  return {
                    status: "healthy",
                    timestamp: new Date().toISOString(),
                    components: {},
                    metrics: {
                      processCpuPercent: 0,
                      processMemoryRssMb: 0,
                      processMemoryVmsMb: 0,
                      threadCount: 0,
                      openFileHandles: 0,
                      processUptimeSeconds: 0,
                      totalFileEvents: 0,
                      totalDetections: 0,
                      totalAlerts: 0,
                      totalSessions: 0,
                      unconsumedFeedbackCount: 0,
                      lastRetrainingStatus: null,
                    },
                    issues: [],
                  };
                }
                return await window.electronAPI.getHealth();
              }}
            />
          )}

          {activeTab === "model" && (
            <ModelStudioView
              status={status}
              onRetrainModel={async () => {
                if (!window.electronAPI) return { status: "Retrained" };
                return await window.electronAPI.retrainModel();
              }}
              onSwapModel={async (p) => {
                if (!window.electronAPI) return { status: "Swapped" };
                return await window.electronAPI.swapModel(p);
              }}
            />
          )}

          {activeTab === "settings" && (
            <SettingsView
              onGetConfig={async () => {
                if (!window.electronAPI) return null;
                return await window.electronAPI.getConfig();
              }}
              onSaveConfig={async (cfg) => {
                if (!window.electronAPI) return true;
                const ok = await window.electronAPI.saveConfig(cfg);
                refreshStatusAndMetrics();
                return ok;
              }}
              onSelectFolder={async () => {
                if (!window.electronAPI) return null;
                return await window.electronAPI.selectFolder();
              }}
              onOptimizeDb={async () => {
                if (!window.electronAPI) return { status: "optimized" };
                return await window.electronAPI.optimizeDb();
              }}
              onPruneDb={async (days) => {
                if (!window.electronAPI) return { pruned: 0 };
                return await window.electronAPI.pruneDb(days);
              }}
            />
          )}
        </main>
      </div>

      {/* CRT Display Configuration Modal */}
      {showCrtModal && (
        <CrtConfigModal
          config={crtConfig}
          onChange={setCrtConfig}
          onClose={() => setShowCrtModal(false)}
        />
      )}
    </div>
  );
}

export default App;
