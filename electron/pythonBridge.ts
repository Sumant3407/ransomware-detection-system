import { spawn, execFile, ChildProcess } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

export class PythonBridge {
  private pythonPath: string;
  private activeMonitoringProcess: ChildProcess | null = null;
  private isMonitoring = false;

  constructor() {
    this.pythonPath = this.resolvePythonExecutable();
  }

  private resolvePythonExecutable(): string {
    // Check for local virtual environment first
    const venvWindows = path.join(projectRoot, ".venv", "Scripts", "python.exe");
    const venvUnix = path.join(projectRoot, ".venv", "bin", "python");

    if (fs.existsSync(venvWindows)) return venvWindows;
    if (fs.existsSync(venvUnix)) return venvUnix;

    // Fallback to system python
    return process.platform === "win32" ? "python" : "python3";
  }

  public async runCli(args: string[]): Promise<any> {
    return new Promise((resolve, reject) => {
      const fullArgs = ["-m", "app.main", ...args];
      execFile(
        this.pythonPath,
        fullArgs,
        {
          cwd: projectRoot,
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PYTHONUNBUFFERED: "1" },
        },
        (error, stdout, stderr) => {
          if (error && !stdout) {
            return reject(new Error(stderr || error.message));
          }

          // Try to parse stdout as JSON if --json was requested
          if (args.includes("--json")) {
            try {
              const parsed = JSON.parse(stdout.trim());
              return resolve(parsed);
            } catch (err) {
              // If stdout contains mixed logs, try to find JSON block
              const jsonMatch = stdout.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
              if (jsonMatch) {
                try {
                  const extracted = JSON.parse(jsonMatch[0]);
                  return resolve(extracted);
                } catch {
                  // Fall through
                }
              }
              return resolve({ output: stdout, rawError: stderr });
            }
          }

          resolve({ output: stdout, stderr });
        }
      );
    });
  }

  public async getStatus(): Promise<any> {
    return this.runCli(["--status", "--json"]);
  }

  public async getHealth(): Promise<any> {
    return this.runCli(["--health", "--json"]);
  }

  public async getMetrics(): Promise<any> {
    return this.runCli(["--metrics", "--json"]);
  }

  public async getHistory(): Promise<any> {
    return this.runCli(["--history", "--json"]);
  }

  public async getForensics(): Promise<any> {
    return this.runCli(["--forensics", "--json"]);
  }

  public async getSnapshot(snapshotId: number): Promise<any> {
    return this.runCli(["--snapshot-id", snapshotId.toString(), "--json"]);
  }

  public async triggerScan(): Promise<any> {
    return this.runCli(["--scan", "--json"]);
  }

  public async runDemo(action: string, options: { count?: number; steps?: number } = {}): Promise<any> {
    const args = ["--demo", action, "--json"];
    if (options.count) args.push("--demo-count", options.count.toString());
    if (options.steps) args.push("--demo-steps", options.steps.toString());
    return this.runCli(args);
  }

  public async optimizeDb(): Promise<any> {
    return this.runCli(["--optimize-db", "--json"]);
  }

  public async pruneDb(days: number): Promise<any> {
    return this.runCli(["--prune-days", days.toString(), "--json"]);
  }

  public async validateConfig(filePath: string): Promise<any> {
    return this.runCli(["--validate-config", filePath, "--json"]);
  }

  public async swapModel(filePath: string): Promise<any> {
    return this.runCli(["--swap-model", filePath, "--json"]);
  }

  public async retrainModel(): Promise<any> {
    return new Promise((resolve, reject) => {
      execFile(
        this.pythonPath,
        ["scripts/retrainPipeline.py", "--retrain", "--force", "--json"],
        {
          cwd: projectRoot,
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PYTHONUNBUFFERED: "1" },
        },
        (error, stdout, stderr) => {
          if (error && !stdout) return reject(new Error(stderr || error.message));
          try {
            const parsed = JSON.parse(stdout.trim());
            resolve(parsed);
          } catch {
            resolve({ output: stdout, stderr });
          }
        }
      );
    });
  }

  public startMonitoring(
    onData: (data: string) => void,
    onStatusChange: (running: boolean) => void
  ): boolean {
    if (this.activeMonitoringProcess) {
      return false;
    }

    this.activeMonitoringProcess = spawn(
      this.pythonPath,
      ["-m", "app.main", "--monitor", "--hot-reload"],
      {
        cwd: projectRoot,
        env: { ...process.env, PYTHONUNBUFFERED: "1" },
      }
    );

    this.isMonitoring = true;
    onStatusChange(true);

    this.activeMonitoringProcess.stdout?.on("data", (chunk) => {
      onData(chunk.toString());
    });

    this.activeMonitoringProcess.stderr?.on("data", (chunk) => {
      onData(`[STDERR] ${chunk.toString()}`);
    });

    this.activeMonitoringProcess.on("close", () => {
      this.activeMonitoringProcess = null;
      this.isMonitoring = false;
      onStatusChange(false);
    });

    return true;
  }

  public stopMonitoring(): boolean {
    if (this.activeMonitoringProcess) {
      this.activeMonitoringProcess.kill();
      this.activeMonitoringProcess = null;
      this.isMonitoring = false;
      return true;
    }
    return false;
  }

  public getIsMonitoring(): boolean {
    return this.isMonitoring;
  }

  public getConfig(): any {
    const configPath = path.join(projectRoot, "data", "settings.json");
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, "utf-8");
        return JSON.parse(raw);
      } catch (err: any) {
        throw new Error(`Failed to read settings.json: ${err.message}`);
      }
    }
    return null;
  }

  public saveConfig(newConfig: any): boolean {
    const configPath = path.join(projectRoot, "data", "settings.json");
    try {
      fs.writeFileSync(configPath, JSON.stringify(newConfig, null, 2), "utf-8");
      return true;
    } catch (err: any) {
      throw new Error(`Failed to write settings.json: ${err.message}`);
    }
  }
}
