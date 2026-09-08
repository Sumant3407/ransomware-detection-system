# Security Scope

This project is defensive research software. The normal application never executes real ransomware, encrypts files, deletes files, kills processes, changes firewall settings, collects credentials, persists through unknown scripts, or sends telemetry to a remote service.

The simulator is safe and limited to a disposable directory containing the `.lab-simulation` marker. It creates, modifies, and renames generated files only.

Model artifacts are loaded only after structure, feature schema, malicious-label, and checksum validation. Do not load artifacts from untrusted sources. Model activation is separate from training and uses atomic replacement.

The current runtime monitors explicitly configured directories. Exact process attribution, whole-disk monitoring, kernel telemetry, quarantine, and automatic containment require additional security review before implementation.
