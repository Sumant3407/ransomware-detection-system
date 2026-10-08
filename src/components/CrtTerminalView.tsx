import React, { useState, useEffect, useRef } from "react";

interface CrtTerminalViewProps {
  logs: string[];
  onExecuteCommand: (cmd: string) => Promise<string>;
  onClearLogs: () => void;
}

export const CrtTerminalView: React.FC<CrtTerminalViewProps> = ({
  logs,
  onExecuteCommand,
  onClearLogs,
}) => {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isExecuting, setIsExecuting] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed) return;

    if (trimmed.toLowerCase() === "clear") {
      onClearLogs();
      setInput("");
      return;
    }

    setHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setInput("");
    setIsExecuting(true);

    try {
      await onExecuteCommand(trimmed);
    } finally {
      setIsExecuting(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIndex);
      setInput(history[nextIndex]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (history.length === 0 || historyIndex === -1) return;
      const nextIndex = historyIndex + 1;
      if (nextIndex >= history.length) {
        setHistoryIndex(-1);
        setInput("");
      } else {
        setHistoryIndex(nextIndex);
        setInput(history[nextIndex]);
      }
    }
  };

  return (
    <div className="crt-terminal-container" onClick={() => inputRef.current?.focus()}>
      <div className="terminal-screen">
        <div className="terminal-header-banner">
          <span className="terminal-tag">[ZION-MAINFRAME-OS v2.4.0]</span>
          <span className="terminal-tag">[SECURE HOST CONSOLE]</span>
          <span className="terminal-tag">[TYPE 'help' FOR COMMANDS]</span>
        </div>

        <div className="terminal-log-output">
          {logs.map((line, idx) => (
            <div key={idx} className={`log-line ${getLineClass(line)}`}>
              {line}
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>

        <form className="terminal-prompt-form" onSubmit={handleSubmit}>
          <span className="prompt-symbol">root@zion-defense:~#</span>
          <input
            ref={inputRef}
            type="text"
            className="terminal-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isExecuting}
            autoFocus
            spellCheck={false}
            autoComplete="off"
            placeholder={isExecuting ? "Executing command..." : "Enter command (e.g. 'scan', 'demo attack', 'health')..."}
          />
          {isExecuting && <span className="executing-spinner">⟳</span>}
        </form>
      </div>
    </div>
  );
};

function getLineClass(line: string): string {
  if (line.includes("ALERT") || line.includes("CRITICAL") || line.includes("RANSOMWARE") || line.includes("ERROR")) {
    return "log-critical";
  }
  if (line.includes("WARNING") || line.includes("Suspicious") || line.includes("ELEVATED")) {
    return "log-warning";
  }
  if (line.includes("SUCCESS") || line.includes("HEALTHY") || line.includes("Valid") || line.includes("[+]")) {
    return "log-success";
  }
  if (line.startsWith("> ") || line.startsWith("root@")) {
    return "log-command";
  }
  return "log-normal";
}
