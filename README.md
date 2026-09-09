<div align="center">

# AFTERKEY

### The key was revoked. The exposure wasn't.

**Read-only verification for post-revocation secret persistence.**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Mode](https://img.shields.io/badge/Mode-Read--Only-2ea44f)
![Network](https://img.shields.io/badge/Network-None-555)
![Dependencies](https://img.shields.io/badge/Runtime%20Deps-0-555)
![License](https://img.shields.io/badge/License-MIT-blue)

</div>

---

## What is AFTERKEY?

AFTERKEY is a small-footprint defensive security tool for verifying whether known secret material still persists after a credential has been revoked or rotated.

Instead of asking:

> **"Is this credential still valid?"**

AFTERKEY asks:

> **"Where does the old secret still exist?"**

A revoked credential may no longer authorize access, while residual copies of the old secret can still remain inside Git history, build artifacts, container exports, backup directories, or local files.

AFTERKEY makes that remaining exposure visible and measurable.

---

## Why AFTERKEY?

When an API key, token, or other machine secret is exposed, the typical response is:

    Exposure detected
          ↓
    Revoke credential
          ↓
    Rotate credential
          ↓
    Continue operations

This stops authorization.

It does not automatically prove that every copy of the old secret material has disappeared.

Residual copies may still remain in:

- Git history
- build artifacts
- container exports
- backup directories
- archived files
- local application paths

AFTERKEY focuses specifically on this post-revocation stage.

---

## Core workflow

    Exposure detected
          ↓
    Revoke / rotate
          ↓
    AFTERKEY scan
          ↓
    Residual findings
          ↓
    Company-controlled remediation
          ↓
    AFTERKEY rescan
          ↓
    0 residual copies
          ↓
    COMPLETE

> **Detect → Report → Remediate → Rescan → Verify**

---

## Example result

A revoked synthetic secret was intentionally left in three persistence domains while the current application state remained clean.

Initial scan:

    AFTERKEY REPORT
    ====================================================
    Secret ID              : COMPANY-LAB-001
    Mode                   : READ-ONLY
    Lifecycle              : revoked
    Credential validity    : NOT TESTED
    Residual copies        : 3
    Reach domains          : 3
    Eradication state      : INCOMPLETE

    [RESIDUAL] git_history
    [RESIDUAL] artifact
    [RESIDUAL] backup

After organization-controlled remediation:

    3 → 2 → 1 → 0

Final verification:

    Residual copies        : 0
    Reach domains          : 0
    Eradication state      : COMPLETE

AFTERKEY performed verification only.

---

## Design principles

| Principle | AFTERKEY |
|---|---|
| Production scan behavior | Read-only |
| Runtime Python dependencies | 0 |
| Network calls | None |
| Agent / server / database | None |
| Credential validity testing | Not performed |
| Plaintext secret in reports | No |
| Scope | Explicitly manifest-defined |
| Root filesystem scan | Blocked by default |

> **Minimum surface. Maximum evidence.**

---

## Supported sources

| Source type | Status |
|---|---|
| Git history | ✓ |
| Filesystem paths | ✓ |
| Backup directories | ✓ |
| ZIP / build artifacts | ✓ |
| Container exports | ✓ |
| Nested archive layers | ✓ |

---

## Enterprise-safe behavior

AFTERKEY is intentionally conservative in production use.

It does not:

- delete production files
- rewrite production Git history
- revoke credentials
- rotate credentials
- authenticate to external services
- test whether a credential is still valid
- make network calls
- automatically remediate findings

Remediation remains under the control of the organization.

AFTERKEY is designed to verify whether remediation actually removed the known secret from the authorized inspection scope.

---

## Quick start

Check the environment:

    python -m afterkey doctor

Expected output includes:

    Git          : FOUND
    Runtime deps : 0
    Network calls: none
    Default mode : read-only

Run the controlled demo:

    python -m afterkey demo

Windows users can also run:

    run_demo_windows.bat

Expected final state:

    Residual copies   : 0
    Reach domains     : 0
    Eradication state : COMPLETE

The built-in demo uses only a synthetic test secret.

---

## Company usage

A company defines exactly which locations AFTERKEY is allowed to inspect.

Example manifest:

    {
      "schema_version": 1,
      "secret": {
        "id": "INC-2026-0412",
        "fingerprint": "generated-by-afterkey",
        "status": "revoked",
        "revoked_at": "2026-09-09T10:00:00+00:00"
      },
      "settings": {
        "allow_root_scope": false,
        "exclude": [
          "node_modules/**",
          ".venv/**",
          "__pycache__/**",
          "*.tmp"
        ]
      },
      "sources": [
        {
          "name": "payments-repository",
          "type": "git_history",
          "path": "D:\\repos\\payments-api"
        },
        {
          "name": "release-artifact",
          "type": "artifact",
          "path": "D:\\builds\\release.zip"
        },
        {
          "name": "approved-backups",
          "type": "backup",
          "path": "E:\\backups\\payments"
        }
      ]
    }

Run:

    python -m afterkey scan --manifest afterkey.json

The known secret is entered through a hidden prompt.

AFTERKEY does not store the plaintext secret in its evidence reports.

---

## Evidence

AFTERKEY stores scan evidence locally under:

    .afterkey/scans/

Evidence may include:

- secret identifier
- fingerprint prefix
- lifecycle status
- residual copy count
- reach domain count
- finding locations
- eradication state
- scan timestamp

The plaintext secret is not written to the report.

---

## JSON output

Machine-readable output can be generated with:

    python -m afterkey scan --manifest afterkey.json --json

Example:

    {
      "tool": "AFTERKEY",
      "version": "1.1.0",
      "mode": "read-only",
      "secret_id": "INC-2026-0412",
      "credential_validity_tested": false,
      "residual_copies": 3,
      "reach_domains": 2,
      "eradication_state": "incomplete"
    }

This makes AFTERKEY suitable for CI and incident-response workflows.

---

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan completed and no residual copies were found |
| `1` | Scan completed and one or more residual copies were found |
| `2` | Configuration, input, or runtime error |

Example:

    0 → remediation verified
    1 → residual exposure remains
    2 → scan or configuration problem

---

## Scope guard

AFTERKEY scans only explicitly configured sources.

Root filesystem scanning is blocked by default.

Example:

    {
      "settings": {
        "allow_root_scope": false
      }
    }

This reduces the risk of accidentally scanning an entire workstation or server outside the intended investigation scope.

---

## Ignore rules

Organizations can exclude paths or file patterns.

Example:

    {
      "settings": {
        "exclude": [
          "node_modules/**",
          ".venv/**",
          "__pycache__/**",
          "*.tmp"
        ]
      }
    }

This helps keep scans focused and reduces unnecessary evidence noise.

---

## Lifecycle metrics

AFTERKEY can use stored scan history to measure remediation progress.

### Time-to-Eradication

Time between the recorded revocation point and the first verified scan with zero residual copies.

### Residual Half-Life

An experimental AFTERKEY metric measuring the time required for the observed residual copy count to fall to half of its baseline value.

Example:

    Baseline residuals : 4
    Half threshold     : 2

> **Residual Half-Life is an experimental AFTERKEY research metric. It is not a NIST or OWASP metric.**

---

## Threat model

AFTERKEY assumes:

- the secret being traced is already known
- the operator is authorized to inspect the configured sources
- the credential may already have been revoked or rotated
- residual copies may persist after revocation
- remediation is performed by external organizational processes
- AFTERKEY's role is verification, not automatic deletion

AFTERKEY is not intended to replace general-purpose secret discovery platforms.

Its focus is narrower:

> **post-revocation residual persistence and eradication verification**

---

## What AFTERKEY is not

AFTERKEY is not:

- a credential brute-force tool
- a remote authentication tester
- a password cracking tool
- a cloud secrets manager
- a malware scanner
- a general DLP platform
- an automatic cleanup utility

It is a focused defensive security tool for tracking known secret material after revocation.

---

## Research hypothesis

> **Credential revocation can terminate authorization without automatically eradicating every residual copy of the secret material.**

AFTERKEY was built to make that remaining exposure visible and measurable.

---

## Repository structure

    afterkey/
    ├── afterkey/                     # Core CLI and scanner
    ├── lab/                          # Synthetic controlled lab
    ├── tests/                        # Test suite
    ├── ENTERPRISE_GUIDE.md           # Enterprise usage guidance
    ├── SECURITY.md                   # Security boundaries
    ├── enterprise.manifest.example.json
    ├── pyproject.toml
    ├── run_demo_windows.bat
    └── README.md

---

## Controlled validation

The project was validated using a synthetic company-style workflow.

Baseline:

    Residual copies : 3
    Reach domains   : 3
    State           : INCOMPLETE

Remediation lifecycle:

    3 → 2 → 1 → 0

Final state:

    Residual copies : 0
    Reach domains   : 0
    State           : COMPLETE

The test environment used synthetic secrets only.

---

## Security

Use AFTERKEY only on:

- systems you own
- repositories you are authorized to inspect
- backups you are authorized to inspect
- artifacts you are authorized to inspect
- secrets you are authorized to trace

For additional guidance, see:

- [`SECURITY.md`](SECURITY.md)
- [`ENTERPRISE_GUIDE.md`](ENTERPRISE_GUIDE.md)

---

## License

MIT License.

See [`LICENSE`](LICENSE).

---

<div align="center">

### AFTERKEY

**The key was revoked. The exposure wasn't.**

**Minimum surface. Maximum evidence.**

</div>
