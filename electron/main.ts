import { app, BrowserWindow, ipcMain, dialog } from "electron";
import * as path from "path";
import { fileURLToPath } from "url";
import { PythonBridge } from "./pythonBridge.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow: BrowserWindow | null = null;
const pythonBridge = new PythonBridge();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#000000",
    title: "Zion Mainframe — Ransomware Defense Station",
    frame: true,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      webgl: true,
    },
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow?.show();
  });

  const devServerUrl = process.env.VITE_DEV_SERVER_URL;

  if (devServerUrl) {
    mainWindow.loadURL(devServerUrl).catch(() => {
      const indexPath = path.join(__dirname, "../dist/index.html");
      mainWindow?.loadFile(indexPath);
    });
  } else {
    const indexPath = path.join(__dirname, "../dist/index.html");
    mainWindow.loadFile(indexPath);
  }

  mainWindow.on("closed", () => {
    pythonBridge.stopMonitoring();
    mainWindow = null;
  });
}

// Register IPC handlers
ipcMain.handle("api:get-status", async () => {
  return await pythonBridge.getStatus();
});

ipcMain.handle("api:get-health", async () => {
  return await pythonBridge.getHealth();
});

ipcMain.handle("api:get-metrics", async () => {
  return await pythonBridge.getMetrics();
});

ipcMain.handle("api:get-history", async () => {
  return await pythonBridge.getHistory();
});

ipcMain.handle("api:get-forensics", async () => {
  return await pythonBridge.getForensics();
});

ipcMain.handle("api:get-snapshot", async (_event, id: number) => {
  return await pythonBridge.getSnapshot(id);
});

ipcMain.handle("api:trigger-scan", async () => {
  return await pythonBridge.triggerScan();
});

ipcMain.handle("api:run-demo", async (_event, action: string, options?: any) => {
  return await pythonBridge.runDemo(action, options);
});

ipcMain.handle("api:retrain-model", async () => {
  return await pythonBridge.retrainModel();
});

ipcMain.handle("api:optimize-db", async () => {
  return await pythonBridge.optimizeDb();
});

ipcMain.handle("api:prune-db", async (_event, days: number) => {
  return await pythonBridge.pruneDb(days);
});

ipcMain.handle("api:validate-config", async (_event, filePath: string) => {
  return await pythonBridge.validateConfig(filePath);
});

ipcMain.handle("api:swap-model", async (_event, filePath: string) => {
  return await pythonBridge.swapModel(filePath);
});

ipcMain.handle("api:get-config", async () => {
  return pythonBridge.getConfig();
});

ipcMain.handle("api:save-config", async (_event, config: any) => {
  return pythonBridge.saveConfig(config);
});

ipcMain.handle("api:select-folder", async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openDirectory"],
    title: "Select Directory to Protect",
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});

ipcMain.handle("api:start-monitoring", async () => {
  return pythonBridge.startMonitoring(
    (logLine) => {
      mainWindow?.webContents.send("monitoring:log", logLine);
    },
    (status) => {
      mainWindow?.webContents.send("monitoring:status", status);
    }
  );
});

ipcMain.handle("api:stop-monitoring", async () => {
  return pythonBridge.stopMonitoring();
});

ipcMain.handle("api:is-monitoring", async () => {
  return pythonBridge.getIsMonitoring();
});

ipcMain.handle("api:execute-command", async (_event, rawCmd: string) => {
  const trimmed = rawCmd.trim();
  if (!trimmed) return "";

  const parts = trimmed.split(/\s+/);
  const command = parts[0].toLowerCase();
  const rest = parts.slice(1);

  switch (command) {
    case "help":
      return [
        "AVAILABLE ZION DEFENSE COMMANDS:",
        "  status             - Display protection status and monitored paths",
        "  health             - Run comprehensive subsystem health check",
        "  metrics            - Display real-time process CPU, RAM, & detections",
        "  scan               - Perform an immediate one-time threat scan",
        "  monitor start      - Start real-time background protection daemon",
        "  monitor stop       - Stop background protection daemon",
        "  history            - Display recent detection history",
        "  forensics          - List captured forensic incident snapshots",
        "  snapshot <id>      - Inspect detailed forensic snapshot and process tree",
        "  demo benign [N]    - Generate N benign documents in test sandbox",
        "  demo normal [N]    - Simulate normal office editing activity",
        "  demo attack [N]    - Simulate sandboxed ransomware attack burst",
        "  demo clean         - Reset and clean sandbox directory",
        "  optimize           - Run SQLite WAL optimization and vacuum",
        "  retrain            - Execute ML model automated retraining pipeline",
        "  clear              - Clear terminal screen",
      ].join("\n");

    case "status":
      const statusRes = await pythonBridge.getStatus();
      return JSON.stringify(statusRes, null, 2);

    case "health":
      const healthRes = await pythonBridge.getHealth();
      return JSON.stringify(healthRes, null, 2);

    case "metrics":
      const metricsRes = await pythonBridge.getMetrics();
      return JSON.stringify(metricsRes, null, 2);

    case "scan":
      const scanRes = await pythonBridge.triggerScan();
      return JSON.stringify(scanRes, null, 2);

    case "monitor":
      if (rest[0] === "start") {
        const started = pythonBridge.startMonitoring(
          (logLine) => mainWindow?.webContents.send("monitoring:log", logLine),
          (running) => mainWindow?.webContents.send("monitoring:status", running)
        );
        return started ? "[+] Live protection started." : "[!] Monitoring already running.";
      } else if (rest[0] === "stop") {
        const stopped = pythonBridge.stopMonitoring();
        return stopped ? "[-] Live protection stopped." : "[!] Monitoring was not running.";
      }
      return "Usage: monitor start | monitor stop";

    case "history":
      const histRes = await pythonBridge.getHistory();
      return JSON.stringify(histRes, null, 2);

    case "forensics":
      const foreRes = await pythonBridge.getForensics();
      return JSON.stringify(foreRes, null, 2);

    case "snapshot":
      const snapId = parseInt(rest[0], 10);
      if (isNaN(snapId)) return "Usage: snapshot <id>";
      const snapRes = await pythonBridge.getSnapshot(snapId);
      return JSON.stringify(snapRes, null, 2);

    case "demo":
      const demoSub = rest[0];
      const count = parseInt(rest[1] || "25", 10);
      if (!["benign", "normal", "attack", "clean"].includes(demoSub)) {
        return "Usage: demo benign [N] | demo normal [steps] | demo attack [N] | demo clean";
      }
      const demoRes = await pythonBridge.runDemo(demoSub, {
        count: isNaN(count) ? 25 : count,
        steps: isNaN(count) ? 10 : count,
      });
      return JSON.stringify(demoRes, null, 2);

    case "optimize":
      const optRes = await pythonBridge.optimizeDb();
      return JSON.stringify(optRes, null, 2);

    case "retrain":
      const retrainRes = await pythonBridge.retrainModel();
      return JSON.stringify(retrainRes, null, 2);

    default:
      return `Unknown command: "${command}". Type "help" for a list of commands.`;
  }
});

ipcMain.handle("window:minimize", () => {
  mainWindow?.minimize();
});

ipcMain.handle("window:maximize", () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});

ipcMain.handle("window:close", () => {
  mainWindow?.close();
});

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  pythonBridge.stopMonitoring();
  if (process.platform !== "darwin") {
    app.quit();
  }
});
