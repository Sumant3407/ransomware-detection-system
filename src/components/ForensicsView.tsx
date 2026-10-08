import React, { useState, useEffect } from "react";
import { ForensicSnapshot } from "../types/electron";

interface ForensicsViewProps {
  onFetchForensics: () => Promise<ForensicSnapshot[]>;
  onFetchSnapshot: (id: number) => Promise<ForensicSnapshot>;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  onFetchForensics,
  onFetchSnapshot,
}) => {
  const [snapshots, setSnapshots] = useState<ForensicSnapshot[]>([]);
  const [selectedSnapshot, setSelectedSnapshot] = useState<ForensicSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSnapshots = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await onFetchForensics();
      setSnapshots(Array.isArray(data) ? data : []);
      if (Array.isArray(data) && data.length > 0 && !selectedSnapshot) {
        loadDetail(data[0].snapshotId);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load forensic snapshots");
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (id: number) => {
    try {
      const detail = await onFetchSnapshot(id);
      setSelectedSnapshot(detail);
    } catch (err: any) {
      setError(`Failed to load details for snapshot #${id}: ${err.message}`);
    }
  };

  useEffect(() => {
    loadSnapshots();
  }, []);

  const copyJsonReport = () => {
    if (!selectedSnapshot) return;
    navigator.clipboard.writeText(JSON.stringify(selectedSnapshot, null, 2));
    alert("Forensic incident JSON report copied to clipboard!");
  };

  return (
    <div className="view-container">
      <div className="toolbar-panel">
        <div className="toolbar-left">
          <div className="panel-title">🔍 FORENSIC EVIDENCE SNAPSHOTS & PROCESS LINEAGE</div>
        </div>
        <div className="toolbar-right">
          <button className="btn-action btn-primary" onClick={loadSnapshots} disabled={loading}>
            {loading ? "Loading..." : "🔄 REFRESH SNAPSHOTS"}
          </button>
        </div>
      </div>

      {error && <div className="alert-box alert-danger">{error}</div>}

      <div className="forensics-layout">
        {/* Left column: Snapshot List */}
        <div className="panel-card forensics-list-panel">
          <div className="panel-header-row">
            <span className="panel-title">INCIDENT SNAPSHOTS ({snapshots.length})</span>
          </div>

          <div className="snapshot-list-wrapper">
            {snapshots.length === 0 ? (
              <div className="empty-text">No forensic incidents recorded yet.</div>
            ) : (
              snapshots.map((s) => (
                <div
                  key={s.snapshotId}
                  className={`snapshot-card-item ${
                    selectedSnapshot?.snapshotId === s.snapshotId ? "active" : ""
                  }`}
                  onClick={() => loadDetail(s.snapshotId)}
                >
                  <div className="snapshot-header-row">
                    <span className="snapshot-id-tag">#{s.snapshotId}</span>
                    <span
                      className={`badge-classification ${
                        s.classification.includes("ransomware") ? "badge-danger" : "badge-warning"
                      }`}
                    >
                      {s.classification.toUpperCase()}
                    </span>
                  </div>
                  <div className="snapshot-time">{s.capturedAt}</div>
                  <div className="snapshot-proc">
                    Process: <strong>{s.processName || "unknown"}</strong> (PID: {s.processId || "—"})
                  </div>
                  <div className="snapshot-risk">Risk Score: {(s.riskScore * 100).toFixed(1)}%</div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right column: Selected Incident Details */}
        <div className="panel-card forensics-detail-panel">
          {selectedSnapshot ? (
            <div className="forensics-detail-content">
              <div className="detail-header-row">
                <div>
                  <h3 className="detail-title">
                    Incident Snapshot #{selectedSnapshot.snapshotId} Evidence
                  </h3>
                  <div className="detail-meta">Captured at {selectedSnapshot.capturedAt}</div>
                </div>
                <button className="btn-action btn-secondary" onClick={copyJsonReport}>
                  📋 EXPORT JSON REPORT
                </button>
              </div>

              {/* Process Ancestry Tree */}
              <div className="detail-section">
                <div className="section-title">🌲 PROCESS ANCESTRY TREE & ATTRIBUTION</div>
                <div className="process-tree-box">
                  {selectedSnapshot.processTree && selectedSnapshot.processTree.length > 0 ? (
                    selectedSnapshot.processTree.map((node, idx) => (
                      <div key={idx} className="process-tree-node">
                        <span className="tree-indent">{"　".repeat(idx)}{idx > 0 ? "└─ " : "► "}</span>
                        <span className="tree-proc-name">{node.name}</span>
                        <span className="tree-proc-pid">(PID: {node.pid})</span>
                        {node.ppid && <span className="tree-proc-ppid">PPID: {node.ppid}</span>}
                        {node.cmdline && <span className="tree-proc-cmd">"{node.cmdline}"</span>}
                      </div>
                    ))
                  ) : (
                    <div className="process-tree-node">
                      ► {selectedSnapshot.processName || "System Worker"} (PID: {selectedSnapshot.processId || "N/A"})
                    </div>
                  )}
                </div>
              </div>

              {/* Affected Files & Path Hashes */}
              <div className="detail-section">
                <div className="section-title">📁 AFFECTED FILE TARGETS & CRYPTOGRAPHIC HASHES</div>
                <div className="affected-paths-box">
                  {selectedSnapshot.affectedPaths && selectedSnapshot.affectedPaths.length > 0 ? (
                    selectedSnapshot.affectedPaths.map((p, idx) => (
                      <div key={idx} className="affected-path-item">
                        <span className="bullet">▪</span>
                        <span className="path-hash">{p}</span>
                      </div>
                    ))
                  ) : (
                    <div className="empty-text">No target path hashes associated.</div>
                  )}
                </div>
              </div>

              {/* Behavioral Evidence */}
              {selectedSnapshot.evidence && (
                <div className="detail-section">
                  <div className="section-title">🔬 INFERENCE EVIDENCE SNAPSHOT</div>
                  <pre className="evidence-json-block">
                    {JSON.stringify(selectedSnapshot.evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-text flex-center">
              Select an incident snapshot from the list to inspect forensic lineage and process trees.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
