from __future__ import annotations
import fnmatch, hashlib, io, json, shutil, subprocess, tarfile, zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

MAX_MEMBER = 10 * 1024 * 1024
MAX_DEPTH = 2

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def fingerprint(secret: bytes):
    return hashlib.sha256(secret).hexdigest()

@dataclass
class Finding:
    source_name: str
    source_type: str
    location: str
    status: str = "residual"
    detail: str | None = None
    def d(self):
        return asdict(self)

def stream_contains(path: Path, needle: bytes, max_bytes: int):
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return False
        overlap = max(len(needle) - 1, 0)
        prev = b""
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    return False
                data = prev + chunk
                if needle in data:
                    return True
                prev = data[-overlap:] if overlap else b""
    except OSError:
        return False

def is_ignored(rel: str, patterns: list[str]):
    norm = rel.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(Path(norm).name, pat) for pat in patterns)

def scan_dir(name, typ, root: Path, needle: bytes, max_bytes: int, excludes: list[str]):
    out = []
    if not root.exists():
        return out
    for p in root.rglob("*"):
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            rel = p.name
        if ".git" in p.parts or is_ignored(rel, excludes):
            continue
        if stream_contains(p, needle, max_bytes):
            out.append(Finding(name, typ, str(p)))
    return out

def scan_nested(name, typ, data: bytes, logical: str, needle: bytes, max_bytes: int,
                depth: int, max_depth: int, excludes: list[str]):
    if len(data) > max_bytes or depth > max_depth:
        return []
    out = []
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for i in z.infolist():
                    if i.is_dir() or i.file_size > max_bytes or is_ignored(i.filename, excludes):
                        continue
                    try:
                        member = z.read(i.filename)
                    except Exception:
                        continue
                    loc = f"{logical}!/{i.filename}"
                    nested = scan_nested(name, typ, member, loc, needle, max_bytes, depth + 1, max_depth, excludes)
                    if nested:
                        out += nested
                    elif needle in member:
                        out.append(Finding(name, typ, loc))
        except zipfile.BadZipFile:
            pass
        return out

    if logical.lower().endswith((".tar", ".tar.gz", ".tgz", ".layer")):
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
                for m in t.getmembers():
                    if not m.isfile() or m.size > max_bytes or is_ignored(m.name, excludes):
                        continue
                    f = t.extractfile(m)
                    if not f:
                        continue
                    member = f.read()
                    loc = f"{logical}!/{m.name}"
                    nested = scan_nested(name, typ, member, loc, needle, max_bytes, depth + 1, max_depth, excludes)
                    if nested:
                        out += nested
                    elif needle in member:
                        out.append(Finding(name, typ, loc))
        except tarfile.TarError:
            pass
    return out

def scan_archive(name, typ, path: Path, needle: bytes, max_bytes: int, max_depth: int, excludes: list[str]):
    if not path.exists() or not path.is_file():
        return []
    try:
        if path.stat().st_size > max_bytes * 100:
            return [Finding(name, typ, str(path), status="skipped", detail="archive exceeds bounded scan limit")]
        data = path.read_bytes()
    except OSError:
        return []
    return scan_nested(name, typ, data, str(path), needle, max_bytes, 0, max_depth, excludes)

def scan_git(name, repo: Path, needle: bytes):
    if not (repo / ".git").exists() or shutil.which("git") is None:
        return []
    try:
        p = subprocess.Popen(
            ["git", "-C", str(repo), "log", "--all", "-p", "--no-ext-diff", "--no-color"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return []
    commit = None
    hit = None
    try:
        for line in iter(p.stdout.readline, b""):
            if line.startswith(b"commit "):
                commit = line.split(maxsplit=1)[1].strip().decode("ascii", "ignore")
            if needle in line:
                hit = commit
                break
    finally:
        try:
            p.kill()
            p.wait(timeout=2)
        except Exception:
            pass
        try:
            if p.stdout:
                p.stdout.close()
        except Exception:
            pass
    if hit is None:
        return []
    return [Finding(name, "git_history", str(repo), detail=f"secret material observed near commit {hit[:12]}")]

def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def save(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def resolve(manifest_path: Path, value: str):
    p = Path(value).expanduser()
    return p.resolve() if p.is_absolute() else (manifest_path.parent / p).resolve()

def is_filesystem_root(path: Path):
    try:
        return path == Path(path.anchor)
    except Exception:
        return False

def validate_source_scope(path: Path, allow_root_scope: bool):
    if is_filesystem_root(path) and not allow_root_scope:
        raise ValueError(
            f"Refusing root-scope scan: {path}. "
            "Set settings.allow_root_scope=true only after explicit authorization."
        )

def scan_manifest(manifest_path: Path, secret: bytes):
    manifest_path = manifest_path.resolve()
    m = load(manifest_path)
    actual = fingerprint(secret)
    if actual != m["secret"]["fingerprint"]:
        raise ValueError("Secret does not match manifest fingerprint.")

    st = m.get("settings", {})
    max_bytes = int(st.get("max_member_bytes", MAX_MEMBER))
    max_depth = int(st.get("max_archive_depth", MAX_DEPTH))
    allow_root = bool(st.get("allow_root_scope", False))
    global_excludes = list(st.get("exclude", []))

    findings = []
    for s in m.get("sources", []):
        typ = s["type"]
        name = s.get("name", typ)
        path = resolve(manifest_path, s["path"])
        validate_source_scope(path, allow_root)

        required = bool(s.get("required", True))
        if not path.exists():
            if required:
                raise FileNotFoundError(f"Required source does not exist: {path}")
            findings.append(Finding(name, typ, str(path), status="skipped", detail="optional source missing"))
            continue

        excludes = global_excludes + list(s.get("exclude", []))
        if typ in ("filesystem", "backup"):
            findings += scan_dir(name, typ, path, secret, max_bytes, excludes)
        elif typ == "git_history":
            findings += scan_git(name, path, secret)
        elif typ in ("artifact", "archive", "container_export"):
            findings += scan_archive(name, typ, path, secret, max_bytes, max_depth, excludes)
        else:
            findings.append(Finding(name, typ, str(path), status="unsupported"))

    residual = [x for x in findings if x.status == "residual"]
    domains = sorted({x.source_type for x in residual})
    return {
        "tool": "AFTERKEY",
        "version": "1.1.0",
        "mode": "read-only",
        "scan_time": utc_now(),
        "secret_id": m["secret"]["id"],
        "fingerprint_prefix": actual[:16],
        "lifecycle": m["secret"].get("status", "unknown"),
        "revoked_at": m["secret"].get("revoked_at"),
        "credential_validity_tested": False,
        "residual_copies": len(residual),
        "reach_domains": len(domains),
        "domains": domains,
        "eradication_state": "complete" if not residual else "incomplete",
        "findings": [x.d() for x in findings],
    }

def record(project: Path, result: dict):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    p = project / ".afterkey" / "scans" / f"{stamp}.json"
    save(p, result)
    return p

def load_scans(project: Path):
    d = project / ".afterkey" / "scans"
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        try:
            out.append(load(p))
        except Exception:
            pass
    return out

def parse_time(v):
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None

def tte(scans, revoked_at):
    r = parse_time(revoked_at)
    if not r:
        return {"status": "unavailable"}
    rows = []
    for s in scans:
        d = parse_time(s.get("scan_time"))
        if d and d >= r:
            rows.append((d, s))
    rows.sort(key=lambda x: x[0])
    clean = next((d for d, s in rows if s.get("residual_copies", 0) == 0), None)
    if not clean:
        return {"status": "pending"}
    sec = max(0, int((clean - r).total_seconds()))
    return {"status": "complete", "seconds": sec, "hours": round(sec / 3600, 3)}

def half_life(scans, revoked_at):
    r = parse_time(revoked_at)
    if not r:
        return {"status": "unavailable"}
    rows = []
    for s in scans:
        d = parse_time(s.get("scan_time"))
        if d and d >= r:
            rows.append((d, int(s.get("residual_copies", 0))))
    rows.sort(key=lambda x: x[0])
    if not rows:
        return {"status": "unavailable"}
    base = rows[0][1]
    if base == 0:
        return {"status": "zero-at-baseline", "hours": 0.0}
    threshold = base / 2
    hit = next((d for d, c in rows if c <= threshold), None)
    if not hit:
        return {"status": "pending", "baseline_copies": base, "threshold": threshold}
    sec = max(0, int((hit - r).total_seconds()))
    return {
        "status": "complete",
        "baseline_copies": base,
        "threshold": threshold,
        "hours": round(sec / 3600, 3),
    }
