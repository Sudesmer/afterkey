# AFTERKEY
**The key was revoked. The exposure wasn't.**

AFTERKEY is a small-footprint defensive research tool for measuring whether a **known, authorized high-entropy machine secret** still persists in organization-controlled evidence sources after revocation or rotation.

## Research hypothesis

> Revocation can terminate authorization without automatically eradicating every residual copy of the secret material.

NIST SP 800-57 treats revocation and destruction as separate key-management functions. OWASP's Secrets Management guidance likewise recommends removing revoked/rotated secrets from exposed systems such as code and logs.

## Why this is not a normal secret scanner

AFTERKEY does not try to discover every unknown secret pattern. It starts with a known secret from an authorized remediation workflow and asks:

**Where does this exact secret material still persist after revocation?**

That narrow scope keeps the core small while producing lifecycle evidence.

## v1.0

- zero runtime Python dependencies
- no server, daemon, database or agent
- no network calls
- hidden prompt or stdin secret input
- no plaintext secret in reports
- current filesystem scan
- local Git-history scan
- ZIP/TAR artifact scan
- bounded nested archive scan
- Docker/OCI-style nested TAR layer support
- backup-directory scan
- JSON scan evidence
- Time-to-Eradication (TTE)
- experimental Residual Half-Life
- `doctor` command
- synthetic lab
- lab-only eradication helper
- unit tests

## Scope

AFTERKEY is for high-entropy machine secrets such as API tokens and test keys.

The SHA-256 fingerprint is a correlation identifier, **not a password-storage mechanism**. Do not use AFTERKEY as a password auditing or storage tool.

AFTERKEY intentionally does not validate credentials against remote services, authenticate to cloud APIs, bypass access controls, scan the Internet, perform memory forensics or exfiltrate secret material.

Use only on systems and data you are authorized to inspect.

## Quick start

Requirements: Python 3.11+. Git is required only for Git-history scanning and the included lab.

```bash
python -m afterkey doctor
python lab/setup_lab.py
python -m afterkey scan --manifest afterkey.lab.json
python -m afterkey report --manifest afterkey.lab.json
```

Use the synthetic secret printed by `setup_lab.py`.

Expected first scan:

```text
current app        CLEAN
git history        RESIDUAL
CI artifact        RESIDUAL
container layer    RESIDUAL
backup             RESIDUAL
```

## Demonstrate eradication

```bash
python lab/eradicate.py artifact
python -m afterkey scan --manifest afterkey.lab.json

python lab/eradicate.py container
python -m afterkey scan --manifest afterkey.lab.json

python lab/eradicate.py backup
python -m afterkey scan --manifest afterkey.lab.json

python lab/eradicate.py git
python -m afterkey scan --manifest afterkey.lab.json

python -m afterkey report --manifest afterkey.lab.json
```

**Time-to-Eradication (TTE)** is elapsed time from the recorded revocation event to the first post-revocation scan with zero observed residual copies.

**Residual Half-Life** is an experimental AFTERKEY metric: elapsed time until observed residual copies fall to at most half of the first post-revocation observed count. It is not a NIST or OWASP metric.

## Design principle

**Minimum surface, maximum evidence.**

## References

- NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General  
  https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- OWASP Secrets Management Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## License

MIT


## v1.0.1

- Fixed Windows lab Git-history eradication when `.git` object files are read-only.
- GitHub package no longer includes generated lab evidence.


---

## v1.1 Enterprise-Safe Scan Mode

AFTERKEY is **read-only by design** in production use.

- Explicit manifest scope
- Root-scope guard
- Global/per-source ignore rules
- JSON scan output
- CI-friendly exit codes
- Optional sources
- Zero runtime dependencies
- No network calls
- No credential validity testing
- No production deletion/remediation

Run the controlled lab with:

```bash
python -m afterkey demo
```

See `ENTERPRISE_GUIDE.md` for the recommended company workflow.
