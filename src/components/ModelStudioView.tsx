import React, { useState } from "react";
import { SystemStatus } from "../types/electron";

interface ModelStudioViewProps {
  status: SystemStatus | null;
  onRetrainModel: () => Promise<any>;
  onSwapModel: (path: string) => Promise<any>;
}

export const ModelStudioView: React.FC<ModelStudioViewProps> = ({
  status,
  onRetrainModel,
  onSwapModel,
}) => {
  const [candidatePath, setCandidatePath] = useState("");
  const [isRetraining, setIsRetraining] = useState(false);
  const [isSwapping, setIsSwapping] = useState(false);
  const [retrainResult, setRetrainResult] = useState<any>(null);
  const [swapResult, setSwapResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRetrain = async () => {
    setIsRetraining(true);
    setError(null);
    try {
      const res = await onRetrainModel();
      setRetrainResult(res);
    } catch (err: any) {
      setError(err.message || "Model retraining failed");
    } finally {
      setIsRetraining(false);
    }
  };

  const handleSwap = async () => {
    if (!candidatePath.trim()) return;
    setIsSwapping(true);
    setError(null);
    try {
      const res = await onSwapModel(candidatePath.trim());
      setSwapResult(res);
    } catch (err: any) {
      setError(err.message || "Model swap validation failed");
    } finally {
      setIsSwapping(false);
    }
  };

  return (
    <div className="view-container">
      <div className="toolbar-panel">
        <div className="toolbar-left">
          <div className="panel-title">🧠 MACHINE LEARNING MODEL MANAGEMENT & RETRAINING</div>
        </div>
      </div>

      {error && <div className="alert-box alert-danger">{error}</div>}

      {/* Active Model Overview */}
      <div className="panel-card">
        <div className="panel-title">🔒 CURRENT ACTIVE MODEL ARTIFACT</div>
        <div className="model-info-grid">
          <div className="model-info-item">
            <span className="info-label">MODEL PATH:</span>
            <span className="info-value font-mono">{status?.model.path || "None"}</span>
          </div>
          <div className="model-info-item">
            <span className="info-label">ENCRYPTION STATUS:</span>
            <span className="info-value badge-success">AES-256-GCM (Authenticated at Rest)</span>
          </div>
          <div className="model-info-item">
            <span className="info-label">VALIDATION STATUS:</span>
            <span className={`info-value ${status?.model.valid ? "badge-success" : "badge-danger"}`}>
              {status?.model.valid ? "VALID & LOADED" : "INVALID"}
            </span>
          </div>
          <div className="model-info-item">
            <span className="info-label">CLASSIFIER TYPE:</span>
            <span className="info-value">RandomForestClassifier (16 Behavioral Features)</span>
          </div>
        </div>
      </div>

      {/* Automated Retraining Pipeline */}
      <div className="panel-card">
        <div className="panel-header-row">
          <div>
            <div className="panel-title">⚡ CLOSED-LOOP AUTOMATED RETRAINING PIPELINE</div>
            <div className="panel-sub">
              Collects newly labeled detections, performs 5-fold stratified cross-validation, and auto-promotes improved models.
            </div>
          </div>
          <button
            className="btn-action btn-primary"
            disabled={isRetraining}
            onClick={handleRetrain}
          >
            {isRetraining ? "Retraining in progress..." : "🚀 RUN RETRAINING PIPELINE"}
          </button>
        </div>

        {retrainResult && (
          <div className="retrain-results-box">
            <div className="result-header">Retraining Pipeline Output:</div>
            <pre className="evidence-json-block">
              {JSON.stringify(retrainResult, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Candidate Model Hot-Swapping */}
      <div className="panel-card">
        <div className="panel-title">🔄 ZERO-DOWNTIME CANDIDATE MODEL HOT-SWAP</div>
        <div className="panel-sub">
          Preflight validates encryption integrity, feature schema compatibility, and smoke tests inference before atomic swap.
        </div>

        <div className="input-row">
          <input
            type="text"
            className="text-input font-mono flex-fill"
            placeholder="C:\path\to\candidate_model.joblib"
            value={candidatePath}
            onChange={(e) => setCandidatePath(e.target.value)}
          />
          <button
            className="btn-action btn-secondary"
            disabled={isSwapping || !candidatePath.trim()}
            onClick={handleSwap}
          >
            {isSwapping ? "Validating..." : "TEST & SWAP MODEL"}
          </button>
        </div>

        {swapResult && (
          <div className="retrain-results-box">
            <div className="result-header">Candidate Model Validation Result:</div>
            <pre className="evidence-json-block">
              {JSON.stringify(swapResult, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
