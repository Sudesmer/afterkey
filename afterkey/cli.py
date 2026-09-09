from __future__ import annotations
import argparse, getpass, json, shutil, sys
from pathlib import Path
from .core import load, load_scans, record, save, scan_manifest, fingerprint, tte, half_life

def read_secret(use_stdin: bool):
    data = sys.stdin.buffer.readline().rstrip(b"\r\n") if use_stdin else getpass.getpass(
        "Known secret to trace (hidden): "
    ).encode()
    if not data:
        raise ValueError("Secret cannot be empty.")
    return data

def doctor(_):
    print("AFTERKEY doctor")
    print("=" * 36)
    print(f"Python       : {sys.version.split()[0]}")
    print(f"Git          : {'FOUND' if shutil.which('git') else 'NOT FOUND'}")
    print("Runtime deps : 0")
    print("Network calls: none")
    print("Default mode : read-only")
    return 0

def init_cmd(a):
    project = Path(a.project).resolve()
    project.mkdir(parents=True, exist_ok=True)
    secret = read_secret(a.secret_stdin)
    m = {
        "schema_version": 1,
        "secret": {
            "id": a.secret_id,
            "fingerprint": fingerprint(secret),
            "status": "revoked",
            "revoked_at": a.revoked_at,
        },
        "settings": {
            "max_member_bytes": 10 * 1024 * 1024,
            "max_archive_depth": 2,
            "allow_root_scope": False,
            "exclude": ["node_modules/**", ".venv/**", "__pycache__/**"],
        },
        "sources": [],
    }
    out = project / "afterkey.json"
    save(out, m)
    print(f"Created: {out}")
    print("Plaintext secret was not stored.")
    print("Default scan mode is read-only.")
    return 0

def scan_cmd(a):
    manifest = Path(a.manifest).resolve()
    secret = read_secret(a.secret_stdin)
    r = scan_manifest(manifest, secret)
    saved = record(manifest.parent, r)

    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print("\nAFTERKEY REPORT")
        print("=" * 52)
        print(f"Secret ID              : {r['secret_id']}")
        print(f"Mode                   : {r['mode'].upper()}")
        print(f"Lifecycle              : {r['lifecycle']}")
        print("Credential validity    : NOT TESTED")
        print(f"Residual copies        : {r['residual_copies']}")
        print(f"Reach domains          : {r['reach_domains']}")
        print(f"Eradication state      : {r['eradication_state'].upper()}")
        print(f"Fingerprint prefix     : {r['fingerprint_prefix']}…")
        for f in r["findings"]:
            print(f"  [{f['status'].upper():<11}] {f['source_type']:<18} {f['location']}")
        print(f"\nEvidence saved: {saved}")

    # Enterprise-friendly CI semantics:
    # 0 = clean/complete, 1 = residual found, 2 = configuration/runtime error.
    return 1 if r["residual_copies"] else 0

def report_cmd(a):
    manifest = Path(a.manifest).resolve()
    m = load(manifest)
    ss = load_scans(manifest.parent)
    if not ss:
        raise ValueError("No scan evidence recorded.")
    last = ss[-1]
    rep = {
        "secret_id": last["secret_id"],
        "scan_count": len(ss),
        "latest_scan": last["scan_time"],
        "residual_copies": last["residual_copies"],
        "reach_domains": last["reach_domains"],
        "eradication_state": last["eradication_state"],
        "time_to_eradication": tte(ss, m["secret"].get("revoked_at")),
        "residual_half_life": half_life(ss, m["secret"].get("revoked_at")),
    }
    if a.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    print("\nAFTERKEY LIFECYCLE REPORT")
    print("=" * 52)
    for k, v in rep.items():
        print(f"{k:24}: {v}")
    print("\nResidual Half-Life is an experimental AFTERKEY metric, not a NIST/OWASP metric.")
    return 0

def demo_cmd(_):
    from .demo import main as demo_main
    return demo_main()

def main():
    p = argparse.ArgumentParser(
        prog="afterkey",
        description="Small-footprint post-revocation secret persistence verification tool.",
    )
    s = p.add_subparsers(dest="cmd", required=True)

    q = s.add_parser("doctor")
    q.set_defaults(func=doctor)

    q = s.add_parser("init")
    q.add_argument("--project", default=".")
    q.add_argument("--secret-id", default="AK-0001")
    q.add_argument("--revoked-at", required=True)
    q.add_argument("--secret-stdin", action="store_true")
    q.set_defaults(func=init_cmd)

    q = s.add_parser("scan")
    q.add_argument("--manifest", default="afterkey.json")
    q.add_argument("--secret-stdin", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=scan_cmd)

    q = s.add_parser("report")
    q.add_argument("--manifest", default="afterkey.json")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=report_cmd)

    q = s.add_parser("demo")
    q.set_defaults(func=demo_cmd)

    a = p.parse_args()
    try:
        rc = a.func(a)
        raise SystemExit(0 if rc is None else rc)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"AFTERKEY ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)

if __name__ == "__main__":
    main()
