import json, shutil, subprocess, tarfile, tempfile, unittest, zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from afterkey.core import scan_manifest, fingerprint, half_life, tte

class Tests(unittest.TestCase):
    def test_filesystem_zip_nested_tar(self):
        secret=b"AFTERKEY_UNIT_TEST_SECRET"
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"data").mkdir()
            (root/"data/hit.txt").write_bytes(b"x="+secret)
            with zipfile.ZipFile(root/"artifact.zip","w") as z: z.writestr("nested.txt",b"y="+secret)
            layer_file=root/"layer.txt"; layer_file.write_bytes(b"z="+secret)
            with tarfile.open(root/"layer.tar","w") as t: t.add(layer_file,arcname="layer.txt")
            with tarfile.open(root/"image.tar","w") as t: t.add(root/"layer.tar",arcname="layer.tar")
            m={"secret":{"id":"UT","fingerprint":fingerprint(secret),"status":"revoked","revoked_at":datetime.now(timezone.utc).isoformat()},
               "settings":{"max_member_bytes":1024*1024,"max_archive_depth":2},
               "sources":[{"name":"fs","type":"filesystem","path":"./data"},
                          {"name":"zip","type":"artifact","path":"./artifact.zip"},
                          {"name":"image","type":"container_export","path":"./image.tar"}]}
            p=root/"manifest.json"; p.write_text(json.dumps(m),encoding="utf-8")
            r=scan_manifest(p,secret)
            self.assertEqual(r["residual_copies"],3)
            self.assertEqual(set(r["domains"]),{"filesystem","artifact","container_export"})

    @unittest.skipUnless(shutil.which("git"),"git not installed")
    def test_git_history(self):
        secret=b"AFTERKEY_GIT_TEST_SECRET"
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); repo=root/"repo"; repo.mkdir()
            subprocess.run(["git","init"],cwd=repo,check=True,stdout=subprocess.DEVNULL)
            subprocess.run(["git","config","user.email","u@example.invalid"],cwd=repo,check=True)
            subprocess.run(["git","config","user.name","Unit Test"],cwd=repo,check=True)
            (repo/"a.txt").write_bytes(secret)
            subprocess.run(["git","add","a.txt"],cwd=repo,check=True)
            subprocess.run(["git","commit","-m","secret"],cwd=repo,check=True,stdout=subprocess.DEVNULL)
            (repo/"a.txt").write_text("clean",encoding="utf-8")
            subprocess.run(["git","add","a.txt"],cwd=repo,check=True)
            subprocess.run(["git","commit","-m","clean"],cwd=repo,check=True,stdout=subprocess.DEVNULL)
            m={"secret":{"id":"UTG","fingerprint":fingerprint(secret),"status":"revoked","revoked_at":datetime.now(timezone.utc).isoformat()},
               "sources":[{"name":"git","type":"git_history","path":"./repo"}]}
            p=root/"manifest.json"; p.write_text(json.dumps(m),encoding="utf-8")
            r=scan_manifest(p,secret)
            self.assertEqual(r["residual_copies"],1)
            self.assertEqual(r["findings"][0]["source_type"],"git_history")

    def test_metrics(self):
        rev=datetime(2026,1,1,tzinfo=timezone.utc)
        ss=[{"scan_time":(rev+timedelta(hours=1)).isoformat(),"residual_copies":4},
            {"scan_time":(rev+timedelta(hours=2)).isoformat(),"residual_copies":2},
            {"scan_time":(rev+timedelta(hours=4)).isoformat(),"residual_copies":0}]
        self.assertEqual(half_life(ss,rev.isoformat())["hours"],2.0)
        self.assertEqual(tte(ss,rev.isoformat())["hours"],4.0)

if __name__=="__main__": unittest.main()
