import React from "react";
import { SystemMetrics, SystemStatus } from "../types/electron";

export interface LiveEventItem {
  id: string;
  timestamp: string;
  action: "CREATED" | "MODIFIED" | "DELETED" | "RENAMED" | "ACCESSED";
  processName: string;
  processId: number;
  parentProcessId?: number;
  pathHash: string;
  pathId?: number;
  source: string;
}

interface LiveMonitorViewProps {
  status: SystemStatus | null;
  metrics: SystemMetrics | null;
  isMonitoring: boolean;
  events: LiveEventItem[];
  onToggleMonitoring: () => void;
  onQuickScan: () => void;
  onClearEvents: () => void;
}

export const LiveMonitorView: React.FC<LiveMonitorViewProps> = ({
  status,
  metrics,
  isMonitoring,
  events,
  onToggleMonitoring,
  onQuickScan,
  onClearEvents,
}) => {
  return (
    <div className="view-container">
      {/* Telemetry Quick Cards */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-header">PROTECTION STATE</div>
          <div className={`metric-value ${isMonitoring ? "text-success" : "text-warning"}`}>
            {isMonitoring ? "ACTIVE" : "STANDBY"}
          </div>
          <div className="metric-sub">{status?.monitoringPaths.length || 0} Path(s) Monitored</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">TOTAL FILE EVENTS</div>
          <div className="metric-value text-accent">{metrics?.totalFileEvents ?? status?.database.totalEvents ?? 0}</div>
          <div className="metric-sub">{events.length} in live buffer</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">INCIDENT DETECTIONS</div>
          <div className="metric-value text-danger">{metrics?.totalDetections ?? status?.database.totalDetections ?? 0}</div>
          <div className="metric-sub">{metrics?.totalAlerts ?? 0} Critical Alerts</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">HOST CPU & MEMORY</div>
          <div className="metric-value text-info">
            {metrics?.processCpuPercent.toFixed(1) ?? "0.0"}%
          </div>
          <div className="metric-sub">
            {metrics?.processMemoryRssMb.toFixed(0) ?? "0"} MB RAM / {metrics?.threadCount ?? 0} Threads
          </div>
        </div>
      </div>

      {/* Action Toolbar */}
      <div className="toolbar-panel">
        <div className="toolbar-left">
          <button
            className={`btn-action ${isMonitoring ? "btn-danger" : "btn-success"}`}
            onClick={onToggleMonitoring}
          >
            {isMonitoring ? "⏹ STOP MONITORING" : "▶ START LIVE MONITORING"}
          </button>
          <button className="btn-action btn-primary" onClick={onQuickScan}>
            ⚡ IMMEDIATE SCAN
          </button>
        </div>
        <div className="toolbar-right">
          <button className="btn-action btn-subtle" onClick={onClearEvents}>
            🗑 CLEAR TABLE
          </button>
        </div>
      </div>

      {/* Monitored Folders Summary */}
      <div className="panel-card">
        <div className="panel-title">🛡️ ACTIVELY MONITORED DIRECTORIES</div>
        <div className="paths-list">
          {status?.monitoringPaths && status.monitoringPaths.length > 0 ? (
            status.monitoringPaths.map((p, idx) => (
              <div key={idx} className="path-badge">
                <span className="path-dot" />
                <span className="path-text">{p}</span>
                <span className="path-engine">ReadDirectoryChangesW (Real-time)</span>
              </div>
            ))
          ) : (
            <div className="empty-text">No monitoring paths configured.</div>
          )}
        </div>
      </div>

      {/* Real-time Streaming Table */}
      <div className="panel-card flex-fill">
        <div className="panel-header-row">
          <div className="panel-title">📡 REAL-TIME FILE ACTIVITY STREAM</div>
          <div className="panel-badge">{events.length} Events</div>
        </div>

        <div className="table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>ACTION</th>
                <th>PROCESS NAME</th>
                <th>PID</th>
                <th>PPID</th>
                <th>PATH HASH</th>
                <th>SOURCE</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center empty-cell">
                    {isMonitoring
                      ? "Listening for real-time file system events across protected directories..."
                      : "Monitoring is standby. Click 'START LIVE MONITORING' to observe live file activities."}
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} className={`row-action-${ev.action.toLowerCase()}`}>
                    <td className="font-mono">{ev.timestamp}</td>
                    <td>
                      <span className={`badge-action action-${ev.action.toLowerCase()}`}>
                        {ev.action}
                      </span>
                    </td>
                    <td className="font-bold">{ev.processName || "system"}</td>
                    <td className="font-mono">{ev.processId || "—"}</td>
                    <td className="font-mono">{ev.parentProcessId || "—"}</td>
                    <td className="font-mono text-dim">{ev.pathHash.slice(0, 16)}...</td>
                    <td className="text-dim">{ev.source}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
