# AFTERKEY v1.1.0

Enterprise-safe release focused on post-revocation secret persistence verification.

Key properties:
- read-only production scan mode
- explicit manifest scope
- root-scope guard
- ignore rules
- JSON output
- CI-friendly exit codes
- zero runtime Python dependencies
- no network calls
- no credential validity testing
- lab-only synthetic remediation helpers

Quick validation:

```bash
python -m afterkey doctor
python -m afterkey demo
```

On Windows you can also double-click `run_demo_windows.bat`.
