import json
from pathlib import Path
import pytest
from afterkey.core import fingerprint, scan_manifest

def _manifest(tmp_path, secret, source_path, extra_settings=None):
    settings = {
        "max_member_bytes": 1024*1024,
        "max_archive_depth": 2,
        "allow_root_scope": False,
        "exclude": [],
    }
    if extra_settings:
        settings.update(extra_settings)
    m = {
        "schema_version": 1,
        "secret": {"id": "T1", "fingerprint": fingerprint(secret), "status": "revoked", "revoked_at": None},
        "settings": settings,
        "sources": [{"name": "fs", "type": "filesystem", "path": str(source_path)}],
    }
    p = tmp_path / "m.json"
    p.write_text(json.dumps(m), encoding="utf-8")
    return p

def test_ignore_rule(tmp_path):
    secret = b"TEST_SECRET_XYZ"
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "keep.txt").write_bytes(secret)
    (scope / "skip.tmp").write_bytes(secret)
    m = _manifest(tmp_path, secret, scope, {"exclude": ["*.tmp"]})
    r = scan_manifest(m, secret)
    assert r["residual_copies"] == 1
    assert "keep.txt" in r["findings"][0]["location"]

def test_optional_missing_source(tmp_path):
    secret = b"TEST_SECRET_XYZ"
    m = {
        "schema_version": 1,
        "secret": {"id": "T2", "fingerprint": fingerprint(secret), "status": "revoked", "revoked_at": None},
        "settings": {"allow_root_scope": False},
        "sources": [{"name": "optional", "type": "backup", "path": "missing", "required": False}],
    }
    p = tmp_path / "m.json"
    p.write_text(json.dumps(m), encoding="utf-8")
    r = scan_manifest(p, secret)
    assert r["residual_copies"] == 0
    assert r["findings"][0]["status"] == "skipped"
