import React from "react";

export type ActiveTab =
  | "terminal"
  | "monitor"
  | "demo"
  | "forensics"
  | "diagnostics"
  | "model"
  | "settings";

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  isMonitoring: boolean;
  threatLevel: "low" | "medium" | "high" | "critical";
  riskScore: number;
  onToggleMonitoring: () => void;
  onQuickScan: () => void;
  onOpenCrtSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  isMonitoring,
  threatLevel,
  riskScore,
  onToggleMonitoring,
  onQuickScan,
  onOpenCrtSettings,
}) => {
  const getThreatBadgeClass = () => {
    switch (threatLevel) {
      case "critical":
        return "threat-badge threat-critical";
      case "high":
        return "threat-badge threat-high";
      case "medium":
        return "threat-badge threat-medium";
      default:
        return "threat-badge threat-low";
    }
  };

  return (
    <header className="station-header">
      <div className="header-brand">
        <div className="station-emblem">🛡️</div>
        <div className="brand-text">
          <div className="brand-title">ZION MAINFRAME // DEFENSE STATION</div>
          <div className="brand-subtitle">RANSOMWARE BEHAVIORAL SOC & ML DETECTION SYSTEM</div>
        </div>
      </div>

      <div className="header-status-panel">
        <button
          className={`status-pill ${isMonitoring ? "status-monitoring" : "status-standby"}`}
          onClick={onToggleMonitoring}
          title="Click to toggle real-time protection"
        >
          <span className="pulsing-dot" />
          {isMonitoring ? "PROTECTION: ACTIVE" : "PROTECTION: STANDBY"}
        </button>

        <div className={getThreatBadgeClass()}>
          <span className="threat-label">THREAT:</span>
          <span className="threat-val">{threatLevel.toUpperCase()}</span>
          <span className="threat-score">({(riskScore * 100).toFixed(1)}%)</span>
        </div>

        <button className="btn-quick-scan" onClick={onQuickScan} title="Execute immediate one-time threat scan">
          ⚡ SCAN NOW
        </button>

        <button className="btn-crt-settings" onClick={onOpenCrtSettings} title="CRT Shader & Display Settings">
          📺 CRT CONFIG
        </button>
      </div>

      <nav className="station-tabs">
        <button
          className={`tab-btn ${activeTab === "terminal" ? "active" : ""}`}
          onClick={() => setActiveTab("terminal")}
        >
          📟 CRT TERMINAL
        </button>
        <button
          className={`tab-btn ${activeTab === "monitor" ? "active" : ""}`}
          onClick={() => setActiveTab("monitor")}
        >
          🛡️ LIVE MONITOR
        </button>
        <button
          className={`tab-btn ${activeTab === "demo" ? "active" : ""}`}
          onClick={() => setActiveTab("demo")}
        >
          🧪 DEMO & LAB
        </button>
        <button
          className={`tab-btn ${activeTab === "forensics" ? "active" : ""}`}
          onClick={() => setActiveTab("forensics")}
        >
          🔍 FORENSICS
        </button>
        <button
          className={`tab-btn ${activeTab === "diagnostics" ? "active" : ""}`}
          onClick={() => setActiveTab("diagnostics")}
        >
          🩺 DIAGNOSTICS
        </button>
        <button
          className={`tab-btn ${activeTab === "model" ? "active" : ""}`}
          onClick={() => setActiveTab("model")}
        >
          🧠 ML MODEL
        </button>
        <button
          className={`tab-btn ${activeTab === "settings" ? "active" : ""}`}
          onClick={() => setActiveTab("settings")}
        >
          ⚙️ SETTINGS
        </button>
      </nav>
    </header>
  );
};
