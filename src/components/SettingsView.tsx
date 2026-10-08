import React, { useState, useEffect } from "react";

interface SettingsViewProps {
  onGetConfig: () => Promise<any>;
  onSaveConfig: (cfg: any) => Promise<boolean>;
  onSelectFolder: () => Promise<string | null>;
  onOptimizeDb: () => Promise<any>;
  onPruneDb: (days: number) => Promise<any>;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  onGetConfig,
  onSaveConfig,
  onSelectFolder,
  onOptimizeDb,
  onPruneDb,
}) => {
  const [config, setConfig] = useState<any>(null);
  const [paths, setPaths] = useState<string[]>([]);
  const [sensitivity, setSensitivity] = useState("balanced");
  const [interval, setInterval] = useState(1);
  const [cooldown, setCooldown] = useState(60);
  const [pruneDays, setPruneDays] = useState(30);
  const [isSaving, setIsSaving] = useState(false);
  const [dbResult, setDbResult] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const cfg = await onGetConfig();
      if (cfg) {
        setConfig(cfg);
        setPaths(cfg.monitoring?.paths || []);
        setSensitivity(cfg.monitoring?.sensitivity || "balanced");
        setInterval(cfg.monitoring?.intervalSeconds || 1);
        setCooldown(cfg.monitoring?.alertCooldownSeconds || 60);
      }
    } catch (err: any) {
      console.error("Failed to load config:", err);
    }
  };

  const handleAddFolder = async () => {
    try {
      const selected = await onSelectFolder();
      if (selected && !paths.includes(selected)) {
        setPaths((prev) => [...prev, selected]);
      }
    } catch (err: any) {
      alert(`Could not select folder: ${err.message}`);
    }
  };

  const handleRemoveFolder = (target: string) => {
    setPaths((prev) => prev.filter((p) => p !== target));
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      const updated = {
        ...config,
        monitoring: {
          ...config?.monitoring,
          paths,
          sensitivity,
          intervalSeconds: interval,
          alertCooldownSeconds: cooldown,
        },
      };
      const ok = await onSaveConfig(updated);
      if (ok) {
        alert("Configuration saved successfully! Background watchers will hot-reload automatically.");
      }
    } catch (err: any) {
      alert(`Save failed: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleOptimize = async () => {
    try {
      const res = await onOptimizeDb();
      setDbResult(`Optimization complete: ${JSON.stringify(res)}`);
    } catch (err: any) {
      setDbResult(`Optimization error: ${err.message}`);
    }
  };

  const handlePrune = async () => {
    try {
      const res = await onPruneDb(pruneDays);
      setDbResult(`Prune complete: ${JSON.stringify(res)}`);
    } catch (err: any) {
      setDbResult(`Prune error: ${err.message}`);
    }
  };

  return (
    <div className="view-container">
      <div className="toolbar-panel">
        <div className="toolbar-left">
          <div className="panel-title">⚙️ SYSTEM CONFIGURATION & MONITORED PATHS</div>
        </div>
        <div className="toolbar-right">
          <button className="btn-action btn-success" onClick={handleSave} disabled={isSaving}>
            {isSaving ? "Saving..." : "💾 SAVE SETTINGS"}
          </button>
        </div>
      </div>

      {/* Monitored Folders Management */}
      <div className="panel-card">
        <div className="panel-header-row">
          <div>
            <div className="panel-title">🛡️ PROTECTED DIRECTORIES ({paths.length})</div>
            <div className="panel-sub">Directories actively watched for rapid multi-file operations.</div>
          </div>
          <button className="btn-action btn-primary" onClick={handleAddFolder}>
            📂 BROWSE & ADD FOLDER
          </button>
        </div>

        <div className="paths-manager-list">
          {paths.map((p, idx) => (
            <div key={idx} className="path-manager-row">
              <span className="path-idx">[{idx + 1}]</span>
              <span className="path-str font-mono">{p}</span>
              <button
                className="btn-action btn-danger-subtle"
                onClick={() => handleRemoveFolder(p)}
                title="Remove folder from monitoring"
              >
                ✕ REMOVE
              </button>
            </div>
          ))}
          {paths.length === 0 && (
            <div className="empty-text">No protected directories. Click 'BROWSE & ADD FOLDER' to protect directories.</div>
          )}
        </div>
      </div>

      {/* Detection & Monitoring Parameters */}
      <div className="panel-card">
        <div className="panel-title">🎛️ DETECTION & ALERT PARAMETERS</div>
        <div className="settings-form-grid">
          <div className="form-group">
            <label className="form-label">Detection Sensitivity:</label>
            <select
              className="select-input"
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
            >
              <option value="conservative">Conservative (High confidence only)</option>
              <option value="balanced">Balanced (Recommended for workstations)</option>
              <option value="aggressive">Aggressive (High-security sensitive servers)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Sampling Interval (Seconds):</label>
            <input
              type="number"
              className="number-input"
              value={interval}
              min={1}
              max={10}
              onChange={(e) => setInterval(parseInt(e.target.value, 10) || 1)}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Alert Policy Cooldown (Seconds):</label>
            <input
              type="number"
              className="number-input"
              value={cooldown}
              min={5}
              max={600}
              onChange={(e) => setCooldown(parseInt(e.target.value, 10) || 60)}
            />
          </div>
        </div>
      </div>

      {/* Database Maintenance */}
      <div className="panel-card">
        <div className="panel-title">🗄️ SQLITE DATABASE MAINTENANCE & PRUNING</div>
        <div className="db-actions-row">
          <button className="btn-action btn-secondary" onClick={handleOptimize}>
            ⚡ RUN WAL OPTIMIZE & VACUUM
          </button>
          <div className="prune-group">
            <span>Prune older than</span>
            <input
              type="number"
              className="number-input inline-input"
              value={pruneDays}
              min={1}
              max={365}
              onChange={(e) => setPruneDays(parseInt(e.target.value, 10) || 30)}
            />
            <span>days</span>
            <button className="btn-action btn-warning" onClick={handlePrune}>
              🗑 PRUNE OLD DATA
            </button>
          </div>
        </div>

        {dbResult && (
          <div className="retrain-results-box">
            <div className="result-header">Maintenance Result:</div>
            <pre className="evidence-json-block">{dbResult}</pre>
          </div>
        )}
      </div>
    </div>
  );
};
