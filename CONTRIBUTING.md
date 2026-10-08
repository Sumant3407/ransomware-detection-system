# Contributing to Ransomware Detection System

Thank you for your interest in contributing to the **Ransomware Detection System Using Machine Learning** project! We welcome contributions from developers, security researchers, data scientists, and cybersecurity enthusiasts.

---

## 🛡️ Responsible Disclosure & Security Policy

If you discover a security vulnerability or bypass technique in this project:
- **Do NOT open a public GitHub issue.**
- Review our [Security Hardening Policy](docs/SECURITY.md) and report security findings privately to the project maintainers.
- Dual-use testing capabilities (e.g. lab simulation harnesses) are strictly intended for authorized defensive testing, education, and benchmark evaluations.

---

## 🛠️ Development Workflow

### 1. Fork & Clone Repository
```powershell
git clone https://github.com/your-username/ransomware-detection-system.git
cd ransomware-detection-system
```

### 2. Set Up Virtual Environment & Dependencies
```powershell
# Create virtual environment
python -m venv .venv

# Activate environment
.\.venv\Scripts\Activate.ps1   # On Windows
# source .venv/bin/activate    # On Linux/macOS

# Install Python requirements
pip install -r projectConfig\requirements.txt

# Install Node / Electron frontend dependencies
npm install
```

### 3. Running Test Suites
Before submitting any pull request, ensure all test suites pass without regression:

```powershell
# Run Python pytest test suite
python -m pytest tests/ -v

# Run Electron & React Vite build verification
npm run build:electron
npm run build
```

---

## 📐 Code Style & Architecture Guidelines

- **Python:**
  - Follow PEP 8 guidelines and strict type annotations.
  - Utilize centralized security validators (e.g., `PathValidator` in `app/security/pathValidator.py`).
  - Never introduce unvalidated dynamic file system path resolutions or raw model deserialization.
  - Maintain context manager patterns (`__enter__`, `__exit__`) for all OS file handles, directory watchers, and SQLite database connections.

- **TypeScript / React / WebGL:**
  - Strict TypeScript compilation (`strict: true`).
  - Maintain context isolation and sandboxed IPC boundaries in Electron (`electron/preload.ts` and `electron/main.ts`).
  - Preserve WebGL shader fidelity and clean state management.

---

## 📜 Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Push your branch to your fork and submit a Pull Request against `main`.
4. Ensure all CI/CD automated checks and unit tests pass.

---

## 👥 Authors & Maintainers

- **Sumant Kumar Giri**
- **Rishi Joshi**
- **Harsh Mishra**

Licensed under the [MIT License](LICENSE).
