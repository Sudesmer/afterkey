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

AFTERKEY is a small-footprint defensive security tool designed to verify whether known secret material still persists after a credential has been revoked or rotated.

Instead of asking:

> **"Is this credential still valid?"**

AFTERKEY asks:

> **"Where does the old secret still exist?"**

A credential may no longer authorize access, while residual copies of the old secret can still remain inside Git history, build artifacts, container exports, backup directories, or local files.

AFTERKEY helps make that remaining exposure visible and measurable.

---

## Why AFTERKEY?

When an API key, token, or other machine secret is exposed, the usual response is:

```text
Detect exposure
      ↓
Revoke credential
      ↓
Rotate credential
      ↓
Continue operations

## Core workflow

```text
Exposure detected
      ↓
Revoke / rotate
      ↓
AFTERKEY scan
      ↓
Residual findings
      ↓
Company remediation
      ↓
AFTERKEY rescan
      ↓
0 residual → COMPLETE
