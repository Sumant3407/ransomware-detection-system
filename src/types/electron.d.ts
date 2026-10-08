export interface SubsystemHealth {
  name: string;
  status: "healthy" | "degraded" | "unhealthy";
  message: string;
  latencyMs: number;
  details?: Record<string, any>;
}

export interface HealthReport {
  status: "healthy" | "degraded" | "unhealthy";
  timestamp: string;
  components: Record<string, SubsystemHealth>;
  metrics: {
    processCpuPercent: number;
    processMemoryRssMb: number;
    processMemoryVmsMb: number;
    threadCount: number;
    openFileHandles: number;
    processUptimeSeconds: number;
    totalFileEvents: number;
    totalDetections: number;
    totalAlerts: number;
    totalSessions: number;
    unconsumedFeedbackCount: number;
    lastRetrainingStatus: string | null;
  };
  issues: string[];
}

export interface SystemMetrics {
  processCpuPercent: number;
  processMemoryRssMb: number;
  processMemoryVmsMb: number;
  threadCount: number;
  openFileHandles: number;
  processUptimeSeconds: number;
  totalSessions: number;
  totalFileEvents: number;
  totalDetections: number;
  totalAlerts: number;
  unconsumedFeedbackCount: number;
  lastRetrainingStatus: string | null;
}

export interface SystemStatus {
  version: string;
  monitoringPaths: string[];
  intervalSeconds: number;
  sensitivity: string;
  alertCooldownSeconds: number;
  model: {
    path: string;
    exists: boolean;
    valid: boolean;
    error: string | null;
  };
  database: {
    path: string;
    totalEvents: number;
    totalDetections: number;
    totalSessions: number;
  };
}

export interface DetectionRecord {
  detectionId: number;
  occurredAt: string;
  classification: string;
  riskScore: number;
  actionTaken: string;
}

export interface ForensicSnapshot {
  snapshotId: number;
  detectionId: number | null;
  capturedAt: string;
  processId: number | null;
  processName: string | null;
  parentProcessId: number | null;
  classification: string;
  riskScore: number;
  processTree?: Array<{
    pid: number;
    name: string;
    ppid: number | null;
    cmdline?: string;
  }>;
  affectedPaths?: string[];
  evidence?: Record<string, any>;
  systemMetrics?: Record<string, any>;
}

export interface IElectronAPI {
  getStatus: () => Promise<SystemStatus>;
  getHealth: () => Promise<HealthReport>;
  getMetrics: () => Promise<SystemMetrics>;
  getHistory: () => Promise<DetectionRecord[]>;
  getForensics: () => Promise<ForensicSnapshot[]>;
  getSnapshot: (id: number) => Promise<ForensicSnapshot>;
  triggerScan: () => Promise<{ level: string; score: number; classification: string; action: string }>;
  runDemo: (action: "benign" | "normal" | "attack" | "clean", options?: { count?: number; steps?: number }) => Promise<any>;
  retrainModel: () => Promise<any>;
  optimizeDb: () => Promise<any>;
  pruneDb: (days: number) => Promise<any>;
  validateConfig: (filePath: string) => Promise<any>;
  swapModel: (filePath: string) => Promise<any>;
  getConfig: () => Promise<any>;
  saveConfig: (config: any) => Promise<boolean>;
  selectFolder: () => Promise<string | null>;
  startMonitoring: () => Promise<boolean>;
  stopMonitoring: () => Promise<boolean>;
  isMonitoring: () => Promise<boolean>;
  executeCommand: (cmd: string) => Promise<string>;
  onMonitoringLog: (callback: (log: string) => void) => () => void;
  onMonitoringStatus: (callback: (running: boolean) => void) => () => void;
  minimize: () => Promise<void>;
  maximize: () => Promise<void>;
  close: () => Promise<void>;
}

declare global {
  interface Window {
    electronAPI?: IElectronAPI;
  }
}
