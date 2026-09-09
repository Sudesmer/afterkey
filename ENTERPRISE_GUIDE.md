# AFTERKEY v1.1 — Enterprise-Safe Scan Mode

AFTERKEY is a read-only post-revocation secret persistence verification tool.

## Production principle

**Detect → report → human-controlled remediation → rescan → verify.**

AFTERKEY does not delete files, rewrite Git history, revoke credentials, rotate credentials,
authenticate to remote services, or test whether a credential is still valid.

## Recommended company workflow

1. Revoke/rotate the affected machine secret using the organization's existing process.
2. Create an AFTERKEY manifest with only explicitly authorized local sources.
3. Run AFTERKEY using the known old secret through the hidden prompt.
4. Review residual findings.
5. Remediate using the organization's normal Git/artifact/backup/container controls.
6. Run AFTERKEY again.
7. Close the incident when the authorized scope reports `0 residual / COMPLETE`.

## Scope guard

Root filesystem scans are rejected by default. A manifest must explicitly list authorized sources.

`settings.allow_root_scope` defaults to `false`.

## Ignore rules

Global exclusions are configured under:

```json
"exclude": ["node_modules/**", ".venv/**", "*.tmp"]
```

Filesystem, backup and archive scanning honor these patterns.

## Machine-readable output

```bash
python -m afterkey scan --manifest afterkey.json --json
python -m afterkey report --manifest afterkey.json --json
```

## Exit codes

- `0` — scan completed and no residual copy was found
- `1` — scan completed and one or more residual copies were found
- `2` — configuration/input/runtime error

This makes AFTERKEY suitable for CI and incident-response automation without making it destructive.

## One-command controlled demo

```bash
python -m afterkey demo
```

The demo uses only the built-in synthetic secret and lab-only cleanup helper.

## Important boundary

`lab/eradicate.py` is for the synthetic demo only. It is not a production remediation feature.
