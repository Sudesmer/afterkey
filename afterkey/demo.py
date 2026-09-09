
from __future__ import annotations
import shutil
from pathlib import Path
from .core import scan_manifest, record, load, load_scans, tte, half_life

SECRET = b"AFTERKEY_TEST_01_4f8a2d1e9c"

def _print_scan(r):
    print(f"Residual copies        : {r['residual_copies']}")
    print(f"Reach domains          : {r['reach_domains']}")
    print(f"Eradication state      : {r['eradication_state'].upper()}")
    for f in r["findings"]:
        if f["status"] == "residual":
            print(f"  [RESIDUAL] {f['source_type']:<18} {f['location']}")

def main():
    root = Path(__file__).resolve().parents[1]
    evidence = root / ".afterkey"
    if evidence.exists():
        shutil.rmtree(evidence, ignore_errors=True)

    print("AFTERKEY ONE-COMMAND DEMO")
    print("=" * 52)
    print("Synthetic test secret only; no real credential is used.\n")

    from lab import setup_lab, eradicate
    setup_lab.main()
    manifest = root / "afterkey.lab.json"

    print("\n[Baseline] Expected: 4 residual copies")
    first = scan_manifest(manifest, SECRET)
    record(root, first)
    _print_scan(first)

    print("\n[Lab remediation]")
    eradicate.clean_artifact()
    eradicate.clean_container()
    eradicate.clean_backup()
    eradicate.clean_git()
    print("Lab eradication step complete: all")

    print("\n[Verification] Expected: 0 residual copies / COMPLETE")
    last = scan_manifest(manifest, SECRET)
    record(root, last)
    _print_scan(last)

    m = load(manifest)
    scans = load_scans(root)
    print("\n[Lifecycle]")
    print(f"scan_count              : {len(scans)}")
    print(f"time_to_eradication     : {tte(scans, m['secret'].get('revoked_at'))}")
    print(f"residual_half_life      : {half_life(scans, m['secret'].get('revoked_at'))}")
    print("Residual Half-Life is an experimental AFTERKEY metric, not a NIST/OWASP metric.")

    if first["residual_copies"] != 4 or last["residual_copies"] != 0:
        print("\nDEMO FAIL")
        return 2
    print("\nDEMO PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
