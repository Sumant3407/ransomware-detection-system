import React, { useState } from "react";

interface DemoLabViewProps {
  onRunDemo: (action: "benign" | "normal" | "attack" | "clean", options?: { count?: number; steps?: number }) => Promise<any>;
}

export const DemoLabView: React.FC<DemoLabViewProps> = ({ onRunDemo }) => {
  const [fileCount, setFileCount] = useState(25);
  const [normalSteps, setNormalSteps] = useState(10);
  const [isRunning, setIsRunning] = useState(false);
  const [demoLogs, setDemoLogs] = useState<string[]>([
    "[*] Sandbox initialized at 'testFiles/' with strict PathValidator isolation.",
    "[*] Ready to run harmless workload simulations for demonstration & evaluation.",
  ]);

  const addLog = (msg: string) => {
    const time = new Date().toLocaleTimeString();
    setDemoLogs((prev) => [...prev, `[${time}] ${msg}`]);
  };

  const handleAction = async (action: "benign" | "normal" | "attack" | "clean") => {
    setIsRunning(true);
    addLog(`Initiating demo action: ${action.toUpperCase()}...`);

    try {
      const res = await onRunDemo(action, { count: fileCount, steps: normalSteps });
      if (res && res.error) {
        addLog(`❌ Error: ${res.error}`);
      } else {
        if (action === "benign") {
          addLog(`✅ Successfully created ${res.created ?? fileCount} benign office files in testFiles/ (${res.duration?.toFixed(2) ?? 0}s).`);
        } else if (action === "normal") {
          addLog(`✅ Simulated ${normalSteps} normal user office editing steps. Threat status remained LOW.`);
        } else if (action === "attack") {
          addLog(`🚨 Simulated sandboxed attack burst: ${res.renamed ?? fileCount} files locked & high-entropy encrypted. CRITICAL alert raised!`);
        } else if (action === "clean") {
          addLog(`🧹 Cleaned ${res.deleted ?? 0} files. Demo sandbox directory reset.`);
        }
      }
    } catch (err: any) {
      addLog(`❌ Execution failed: ${err.message}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="view-container">
      {/* Sandbox Isolation Notice */}
      <div className="alert-box alert-info">
        <div className="alert-icon">🛡️</div>
        <div className="alert-content">
          <div className="alert-title">SAFE DEMONSTRATION & LABORATORY SANDBOX</div>
          <div className="alert-body">
            All workload simulations are strictly non-destructive and isolated to the disposable{" "}
            <code>testFiles/</code> directory validated with cryptographic path containment. Real-time file system watchers and ML inference will analyze the generated activity live.
          </div>
        </div>
      </div>

      {/* 4 Simulation Action Cards */}
      <div className="demo-grid">
        {/* Card 1: Generate Benign Files */}
        <div className="demo-card">
          <div className="demo-card-header">
            <span className="demo-icon">📁</span>
            <div className="demo-title">1. GENERATE BENIGN FILES</div>
          </div>
          <div className="demo-desc">
            Creates multi-format realistic office documents (<code>.docx</code>, <code>.xlsx</code>, <code>.pdf</code>, <code>.txt</code>, <code>.csv</code>, <code>.json</code>, <code>.py</code>, <code>.jpg</code>) in the test sandbox.
          </div>
          <div className="demo-control-row">
            <label>File Count:</label>
            <input
              type="number"
              className="demo-number-input"
              value={fileCount}
              min={5}
              max={200}
              onChange={(e) => setFileCount(parseInt(e.target.value, 10) || 25)}
            />
          </div>
          <button
            className="btn-demo btn-primary"
            disabled={isRunning}
            onClick={() => handleAction("benign")}
          >
            {isRunning ? "Generating..." : "📄 CREATE BENIGN FILES"}
          </button>
        </div>

        {/* Card 2: Simulate Normal Activity */}
        <div className="demo-card">
          <div className="demo-card-header">
            <span className="demo-icon">💼</span>
            <div className="demo-title">2. SIMULATE NORMAL WORK</div>
          </div>
          <div className="demo-desc">
            Simulates legitimate human office editing (low entropy, low velocity, normal interval appends). Expected outcome: <strong>Threat Level LOW (Green)</strong>.
          </div>
          <div className="demo-control-row">
            <label>Action Steps:</label>
            <input
              type="number"
              className="demo-number-input"
              value={normalSteps}
              min={2}
              max={50}
              onChange={(e) => setNormalSteps(parseInt(e.target.value, 10) || 10)}
            />
          </div>
          <button
            className="btn-demo btn-success"
            disabled={isRunning}
            onClick={() => handleAction("normal")}
          >
            {isRunning ? "Simulating..." : "📝 SIMULATE NORMAL WORK"}
          </button>
        </div>

        {/* Card 3: Simulate Attack */}
        <div className="demo-card demo-card-danger">
          <div className="demo-card-header">
            <span className="demo-icon">🚨</span>
            <div className="demo-title">3. SIMULATE RANSOMWARE ATTACK</div>
          </div>
          <div className="demo-desc">
            Executes high-velocity mass renames (<code>.locked</code>, <code>.crypto</code>) and high-entropy write bursts strictly in sandbox. Triggers <strong>CRITICAL Alert & Forensics</strong>.
          </div>
          <div className="demo-control-row">
            <label>Target Files:</label>
            <input
              type="number"
              className="demo-number-input"
              value={fileCount}
              min={5}
              max={200}
              onChange={(e) => setFileCount(parseInt(e.target.value, 10) || 25)}
            />
          </div>
          <button
            className="btn-demo btn-danger"
            disabled={isRunning}
            onClick={() => handleAction("attack")}
          >
            {isRunning ? "Attacking..." : "⚠️ SIMULATE ATTACK BURST"}
          </button>
        </div>

        {/* Card 4: Clean Sandbox */}
        <div className="demo-card">
          <div className="demo-card-header">
            <span className="demo-icon">🧹</span>
            <div className="demo-title">4. RESET & CLEAN SANDBOX</div>
          </div>
          <div className="demo-desc">
            Safely deletes all generated demonstration files and simulated locked artifacts from <code>testFiles/</code>, resetting the laboratory state.
          </div>
          <div className="demo-control-row">
            <span className="text-dim">Preserves sandbox root</span>
          </div>
          <button
            className="btn-demo btn-warning"
            disabled={isRunning}
            onClick={() => handleAction("clean")}
          >
            {isRunning ? "Cleaning..." : "🗑 CLEAN SANDBOX"}
          </button>
        </div>
      </div>

      {/* Live Simulation Progress Log */}
      <div className="panel-card flex-fill">
        <div className="panel-header-row">
          <div className="panel-title">📟 LABORATORY SIMULATION CONSOLE LOGS</div>
          <button className="btn-action btn-subtle" onClick={() => setDemoLogs([])}>
            CLEAR LOG
          </button>
        </div>
        <div className="terminal-mini-screen">
          {demoLogs.map((log, idx) => (
            <div key={idx} className="terminal-log-row">
              {log}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
