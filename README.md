<div align="center">

AFTERKEY

The key was revoked. The exposure wasn't.

Read-only verification for post-revocation secret persistence.







</div>

Why AFTERKEY?

A credential can be revoked while copies of the old secret still remain in places such as:

Git history

build artifacts

container exports

backup directories

local files

AFTERKEY starts with a known, authorized secret and answers a narrower question than a general secret scanner:

Where does the old secret still exist after revocation?

It then lets a security team rescan the same authorized scope until the residual count reaches zero.

How it works

Secret exposure
      │
      ▼
Revoke / rotate
      │
      ▼
AFTERKEY baseline scan
      │
      ├── Git history
      ├── Build artifacts
      ├── Container exports
      ├── Backups
      └── Filesystem
      │
      ▼
Residual findings
      │
      ▼
Company-controlled remediation
      │
      ▼
AFTERKEY rescan
      │
      ▼
0 residual copies → COMPLETE

AFTERKEY verifies. It does not remediate production data.

Example result

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

After remediation by the organization:

3 → 2 → 1 → 0

Residual copies        : 0
Reach domains          : 0
Eradication state      : COMPLETE

Design principles

Principle

AFTERKEY

Production scan behavior

Read-only

Runtime Python dependencies

0

Network calls

None

Agent / server / database

None

Credential validity testing

Not performed

Plaintext secret in reports

No

Scope

Explicitly manifest-defined

Root filesystem scan

Blocked by default

Minimum surface. Maximum evidence.

Supported sources

Source type

Status

Git history

✓

Filesystem paths

✓

Backup directories

✓

ZIP / build artifacts

✓

Container exports

✓

Nested archive layers

✓

Quick start

1. Check the environment

python -m afterkey doctor

2. Run the controlled demo

python -m afterkey demo

Windows users can also run:

run_demo_windows.bat

Expected final state:

Residual copies   : 0
Reach domains     : 0
Eradication state : COMPLETE

Company usage

Create a manifest containing only the sources the organization has authorized for inspection.

{
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

The known secret is entered through a hidden prompt. AFTERKEY stores a fingerprint for correlation and does not place the plaintext secret in evidence reports.

Exit codes

Code

Meaning

0

Scan completed; no residual copies found

1

Scan completed; residual copies found

2

Configuration, input, or runtime error

This makes AFTERKEY usable in CI and incident-response workflows without turning it into an automatic deletion tool.

Lifecycle metrics

Time-to-Eradication

Time between the recorded revocation point and the first verified scan with zero residual copies.

Residual Half-Life

Experimental AFTERKEY metric for the time required for the observed residual copy count to fall to half of its baseline value.

Residual Half-Life is an experimental AFTERKEY research metric. It is not a NIST or OWASP metric.

Security boundary

AFTERKEY does not:

delete production files

rewrite production Git history

revoke or rotate credentials

authenticate to external services

test whether a credential is still active

make network calls

Production remediation remains under the control of the organization.

Use AFTERKEY only on systems, repositories, artifacts, backups, and credentials you are authorized to inspect.

See SECURITY.md and ENTERPRISE_GUIDE.md.

Research hypothesis

Credential revocation can terminate authorization without automatically eradicating every residual copy of the secret material.

AFTERKEY was built to make that remaining exposure visible and measurable.

License

MIT License.
