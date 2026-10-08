import React, { useState, useEffect } from "react";
import { HealthReport } from "../types/electron";

interface DiagnosticsViewProps {
  onFetchHealth: () => Promise<HealthReport>;
}

export const DiagnosticsView: React.FC<DiagnosticsViewProps> = ({ onFetchHealth }) => {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runDiagnostic = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await onFetchHealth();
      setReport(data);
    } catch (err: any) {
      setError(err.message || "Failed to execute diagnostic health check");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runDiagnostic();
  }, []);

  return (
    <div className="view-container">
      <div className="toolbar-panel">
        <div className="toolbar-left">
          <div className="panel-title">🩺 SUBSYSTEM OBSERVABILITY & SYSTEM DIAGNOSTICS</div>
        </div>
        <div className="toolbar-right">
          <button className="btn-action btn-primary" onClick={runDiagnostic} disabled={loading}>
            {loading ? "Running Diagnostics..." : "🔄 RUN SUBSYSTEM SELF-TEST"}
          </button>
        </div>
      </div>

      {error && <div className="alert-box alert-danger">{error}</div>}

      {/* Overall Status Banner */}
      {report && (
        <div className={`status-banner-card status-banner-${report.status}`}>
          <div className="banner-left">
            <span className="banner-icon">
              {report.status === "healthy" ? "✅" : report.status === "degraded" ? "⚠️" : "❌"}
            </span>
            <div>
              <div className="banner-title">
                SYSTEM HEALTH: {report.status.toUpperCase()}
              </div>
              <div className="banner-sub">Diagnostics evaluated at {report.timestamp}</div>
            </div>
          </div>
          <div className="banner-right">
            <span className="banner-badge">All Subsystems Verified</span>
          </div>
        </div>
      )}

      {/* Subsystems Matrix Cards */}
      <div className="subsystems-grid">
        {report &&
          Object.entries(report.components).map(([key, comp]) => (
            <div key={key} className={`subsystem-card status-border-${comp.status}`}>
              <div className="subsystem-header">
                <div className="subsystem-name">{comp.name.toUpperCase()} SUBSYSTEM</div>
                <span className={`badge-status badge-${comp.status}`}>{comp.status.toUpperCase()}</span>
              </div>
              <div className="subsystem-msg">{comp.message}</div>
              <div className="subsystem-latency">Latency: {comp.latencyMs.toFixed(2)} ms</div>

              {comp.details && (
                <div className="subsystem-details">
                  {Object.entries(comp.details).map(([dKey, dVal]) => (
                    <div key={dKey} className="detail-row">
                      <span className="detail-key">{dKey}:</span>
                      <span className="detail-val">
                        {Array.isArray(dVal) ? `${dVal.length} item(s)` : String(dVal)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
      </div>

      {/* Live Host Telemetry Panel */}
      {report?.metrics && (
        <div className="panel-card">
          <div className="panel-title">📊 HOST PROCESS TELEMETRY & RESOURCES</div>
          <div className="telemetry-grid">
            <div className="telemetry-item">
              <div className="telemetry-label">CPU USAGE</div>
              <div className="telemetry-val">{report.metrics.processCpuPercent.toFixed(1)}%</div>
            </div>
            <div className="telemetry-item">
              <div className="telemetry-label">MEMORY (RSS)</div>
              <div className="telemetry-val">{report.metrics.processMemoryRssMb.toFixed(1)} MB</div>
            </div>
            <div className="telemetry-item">
              <div className="telemetry-label">VIRTUAL MEMORY</div>
              <div className="telemetry-val">{report.metrics.processMemoryVmsMb.toFixed(1)} MB</div>
            </div>
            <div className="telemetry-item">
              <div className="telemetry-label">ACTIVE THREADS</div>
              <div className="telemetry-val">{report.metrics.threadCount}</div>
            </div>
            <div className="telemetry-item">
              <div className="telemetry-label">OPEN FILE HANDLES</div>
              <div className="telemetry-val">{report.metrics.openFileHandles}</div>
            </div>
            <div className="telemetry-item">
              <div className="telemetry-label">UPTIME</div>
              <div className="telemetry-val">{report.metrics.processUptimeSeconds.toFixed(0)}s</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
