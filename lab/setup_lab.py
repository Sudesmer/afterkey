from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, shutil, subprocess, tarfile, zipfile, os, stat
ROOT=Path(__file__).resolve().parent
SECRET="AFTERKEY_TEST_01_4f8a2d1e9c"

def _remove_readonly(func, path, _exc_info):
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    func(path)

def _safe_rmtree(path):
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
    except PermissionError:
        shutil.rmtree(path, onerror=_remove_readonly)

def w(p,t):
    p.parent.mkdir(parents=True,exist_ok=True); p.write_text(t,encoding="utf-8")

def main():
    if shutil.which("git") is None: raise SystemExit("Git is required for the lab.")
    for n in ["app","repo","artifacts","container","backups"]:
        p=ROOT/n
        if p.exists(): _safe_rmtree(p)
        p.mkdir(parents=True)
    w(ROOT/"app/config.ini","mode=production\nsecret=ROTATED_VALUE\n")
    repo=ROOT/"repo"
    subprocess.run(["git","init"],cwd=repo,check=True,stdout=subprocess.DEVNULL)
    subprocess.run(["git","config","user.email","lab@example.invalid"],cwd=repo,check=True)
    subprocess.run(["git","config","user.name","AFTERKEY Lab"],cwd=repo,check=True)
    w(repo/".env",f"API_TOKEN={SECRET}\n")
    subprocess.run(["git","add",".env"],cwd=repo,check=True)
    subprocess.run(["git","commit","-m","lab: add synthetic secret"],cwd=repo,check=True,stdout=subprocess.DEVNULL)
    w(repo/".env","API_TOKEN=ROTATED_VALUE\n")
    subprocess.run(["git","add",".env"],cwd=repo,check=True)
    subprocess.run(["git","commit","-m","lab: rotate secret"],cwd=repo,check=True,stdout=subprocess.DEVNULL)

    temp=ROOT/"artifacts/artifact.env"; w(temp,f"BUILD_TOKEN={SECRET}\n")
    with zipfile.ZipFile(ROOT/"artifacts/build.zip","w",zipfile.ZIP_DEFLATED) as z: z.write(temp,arcname="artifact.env")
    temp.unlink()

    layer_root=ROOT/"container/layer-root"; w(layer_root/"app/runtime.env",f"RUNTIME_TOKEN={SECRET}\n")
    layer_tar=ROOT/"container/layer.tar"
    with tarfile.open(layer_tar,"w") as t: t.add(layer_root,arcname="rootfs")
    with tarfile.open(ROOT/"container/image.tar","w") as t: t.add(layer_tar,arcname="layer.tar")
    shutil.rmtree(layer_root); layer_tar.unlink()

    w(ROOT/"backups/snapshot-001.txt",f"old_secret={SECRET}\n")
    m={"schema_version":1,"secret":{"id":"AK-LAB-0001","fingerprint":hashlib.sha256(SECRET.encode()).hexdigest(),"status":"revoked","revoked_at":datetime.now(timezone.utc).isoformat()},
       "settings":{"max_member_bytes":10*1024*1024,"max_archive_depth":2,"allow_root_scope":False,"exclude":[]},
       "sources":[
         {"name":"current-app","type":"filesystem","path":"./lab/app"},
         {"name":"git-history","type":"git_history","path":"./lab/repo"},
         {"name":"ci-artifact","type":"artifact","path":"./lab/artifacts/build.zip","required":False},
         {"name":"container-export","type":"container_export","path":"./lab/container/image.tar","required":False},
         {"name":"backup","type":"backup","path":"./lab/backups","required":False}]}
    out=ROOT.parent/"afterkey.lab.json"; out.write_text(json.dumps(m,indent=2),encoding="utf-8")
    print("AFTERKEY lab created.")
    print(f"Manifest: {out}")
    print(f"Synthetic lab secret: {SECRET}")
    print("Expected: app CLEAN; Git history, artifact, nested container layer and backup RESIDUAL.")
if __name__=="__main__": main()
