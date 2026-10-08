import { contextBridge, ipcRenderer } from "electron";

const electronAPI = {
  getStatus: () => ipcRenderer.invoke("api:get-status"),
  getHealth: () => ipcRenderer.invoke("api:get-health"),
  getMetrics: () => ipcRenderer.invoke("api:get-metrics"),
  getHistory: () => ipcRenderer.invoke("api:get-history"),
  getForensics: () => ipcRenderer.invoke("api:get-forensics"),
  getSnapshot: (id: number) => ipcRenderer.invoke("api:get-snapshot", id),
  triggerScan: () => ipcRenderer.invoke("api:trigger-scan"),
  runDemo: (action: string, options?: { count?: number; steps?: number }) =>
    ipcRenderer.invoke("api:run-demo", action, options),
  retrainModel: () => ipcRenderer.invoke("api:retrain-model"),
  optimizeDb: () => ipcRenderer.invoke("api:optimize-db"),
  pruneDb: (days: number) => ipcRenderer.invoke("api:prune-db", days),
  validateConfig: (filePath: string) => ipcRenderer.invoke("api:validate-config", filePath),
  swapModel: (filePath: string) => ipcRenderer.invoke("api:swap-model", filePath),
  getConfig: () => ipcRenderer.invoke("api:get-config"),
  saveConfig: (config: any) => ipcRenderer.invoke("api:save-config", config),
  selectFolder: () => ipcRenderer.invoke("api:select-folder"),
  startMonitoring: () => ipcRenderer.invoke("api:start-monitoring"),
  stopMonitoring: () => ipcRenderer.invoke("api:stop-monitoring"),
  isMonitoring: () => ipcRenderer.invoke("api:is-monitoring"),
  executeCommand: (cmd: string) => ipcRenderer.invoke("api:execute-command", cmd),
  onMonitoringLog: (callback: (log: string) => void) => {
    const handler = (_event: any, log: string) => callback(log);
    ipcRenderer.on("monitoring:log", handler);
    return () => ipcRenderer.removeListener("monitoring:log", handler);
  },
  onMonitoringStatus: (callback: (running: boolean) => void) => {
    const handler = (_event: any, running: boolean) => callback(running);
    ipcRenderer.on("monitoring:status", handler);
    return () => ipcRenderer.removeListener("monitoring:status", handler);
  },
  minimize: () => ipcRenderer.invoke("window:minimize"),
  maximize: () => ipcRenderer.invoke("window:maximize"),
  close: () => ipcRenderer.invoke("window:close"),
};

contextBridge.exposeInMainWorld("electronAPI", electronAPI);
