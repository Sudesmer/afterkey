from pathlib import Path
import argparse
import os
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parent


def _make_writable(path: str | Path) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def _remove_readonly(func, path, _exc_info):
    _make_writable(path)
    func(path)


def _safe_rmtree(path: Path) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
    except PermissionError:
        # Git object files may be read-only on Windows.
        shutil.rmtree(path, onerror=_remove_readonly)


def clean_artifact():
    path = ROOT / "artifacts" / "build.zip"
    if path.exists():
        _make_writable(path)
        path.unlink()


def clean_container():
    path = ROOT / "container" / "image.tar"
    if path.exists():
        _make_writable(path)
        path.unlink()


def clean_backup():
    path = ROOT / "backups" / "snapshot-001.txt"
    if path.exists():
        _make_writable(path)
        path.unlink()


def clean_git():
    repo = ROOT / "repo"
    current = (
        (repo / ".env").read_text(encoding="utf-8")
        if (repo / ".env").exists()
        else "API_TOKEN=ROTATED_VALUE\n"
    )

    _safe_rmtree(repo)
    repo.mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.email", "lab@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "AFTERKEY Lab"], cwd=repo, check=True)

    (repo / ".env").write_text(current, encoding="utf-8")
    subprocess.run(["git", "add", ".env"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "lab: sanitized history"],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main():
    parser = argparse.ArgumentParser(description="Safe lab-only eradication helper.")
    parser.add_argument("target", choices=["artifact", "container", "backup", "git", "all"])
    args = parser.parse_args()

    actions = {
        "artifact": clean_artifact,
        "container": clean_container,
        "backup": clean_backup,
        "git": clean_git,
    }

    if args.target == "all":
        for action in actions.values():
            action()
    else:
        actions[args.target]()

    print(f"Lab eradication step complete: {args.target}")


if __name__ == "__main__":
    main()
