AFTERKEY

The key was revoked. The exposure wasn't.

AFTERKEY is a small-footprint defensive security tool for verifying whether known secret material still persists after credential revocation.

Instead of asking:

"Is this credential still valid?"

AFTERKEY asks:

"Where does the old secret still exist?"

A revoked credential may no longer authorize access, while residual copies can remain inside Git history, build artifacts, container exports, backups, or local files.

AFTERKEY provides a read-only way to detect those copies, track remediation progress, and verify when the authorized scope reaches zero residual exposure.

Why AFTERKEY?

Secret scanners are primarily designed to discover exposed credentials.

AFTERKEY focuses on a different stage of the lifecycle:

post-revocation eradication verification.

Typical incident flow:

Secret exposure detected
        ↓
Credential revoked / rotated
        ↓
AFTERKEY baseline scan
        ↓
Residual copies identified
        ↓
Company-controlled remediation
        ↓
AFTERKEY rescan
        ↓
0 residual copies
        ↓
Eradication verified

Core Principle

Detect → Report → Remediate → Rescan → Verify

AFTERKEY is read-only by design during production scanning.

It does not:

delete files

rewrite Git history

revoke credentials

rotate credentials

authenticate to external services

test credential validity

make network calls

Remediation remains under the control of the organization.

Supported Persistence Domains

AFTERKEY can currently inspect authorized local sources including:

Git history

filesystem paths

backup directories

ZIP/build artifacts

container exports and nested archive layers

Example

A revoked synthetic secret was intentionally left in three persistence domains while the current application state remained clean.

Initial verification:

Mode               : READ-ONLY
Residual copies    : 3
Reach domains      : 3
Eradication state  : INCOMPLETE

[RESIDUAL] git_history
[RESIDUAL] artifact
[RESIDUAL] backup

After controlled remediation by the simulated organization:

Observed lifecycle: 3 -> 2 -> 1 -> 0
Final state: COMPLETE

AFTERKEY performed verification only.

Enterprise-Safe Design

Explicit manifest-defined scope

Root filesystem scanning blocked by default

Read-only production behavior

Ignore/exclusion rules

JSON evidence output

CI-friendly exit codes

Zero runtime Python dependencies

No agent

No server

No database

No cloud credentials

No network calls

Minimum surface. Maximum evidence.

Quick Start

Check the environment:

python -m afterkey doctor

Run the controlled synthetic demo:

python -m afterkey demo

Expected result:

Residual copies   : 0
Reach domains     : 0
Eradication state : COMPLETE

Windows users can also run:

run_demo_windows.bat

Production Scan

Create a manifest containing only explicitly authorized sources.

Example:

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

Then run:

python -m afterkey scan --manifest afterkey.json

The known secret is entered through a hidden prompt.

AFTERKEY does not store the plaintext secret in its evidence report.

Exit Codes

0 = scan completed, no residual copies found
1 = scan completed, residual copies found
2 = configuration / runtime error

This allows AFTERKEY to be integrated into incident-response and CI workflows without making the tool destructive.

Experimental Metrics

AFTERKEY can track:

Time-to-Eradication (TTE)
Time between revocation and the first verified zero-residual state.

Residual Half-Life
Experimental AFTERKEY metric measuring how long it takes for observed residual copies to fall to half the baseline count.

Residual Half-Life is an experimental AFTERKEY research metric and is not a NIST or OWASP metric.

Research Hypothesis

Credential revocation can terminate authorization without automatically eradicating every residual copy of the secret material.

AFTERKEY was built to make that remaining exposure visible and measurable.

Security Boundary

Use AFTERKEY only on systems, repositories, backups, artifacts, and credentials you are authorized to inspect.

See SECURITY.md and ENTERPRISE_GUIDE.md for additional guidance.

License

MIT License
