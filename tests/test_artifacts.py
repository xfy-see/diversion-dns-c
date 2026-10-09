import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import artifacts as a

# 以小型虚拟可执行载荷检查验证器的拒绝边界；这里不会执行这些字节。
COMMIT='a'*40


def fixture():
    names=['builds/native/mosdns-c',*['builds/native/tests/'+t for t in a.TESTS]]
    files={n:b'test-program' for n in names}
    m=dict(schema=1,repository=a.REPO,commit=COMMIT,run_id=123,run_attempt=1,target='macos-arm64',kind='native',
           git_tree={},profiles={'native':dict(application=names[0],tests=dict(zip(a.TESTS,names[1:])))},
           files={n:dict(bytes=len(b),sha256=a.digest(b),mode=0o755) for n,b in files.items()})
    return m,files


def archive(path,m,files,extras=()):
    with tarfile.open(path,'w:gz') as tar:
        rows=[('manifest.json',json.dumps(m).encode(),None),*[(n,b,None) for n,b in files.items()],*extras]
        for name,b,kind in rows:
            info=tarfile.TarInfo(name); info.size=len(b)
            if kind: info.type=kind; info.linkname='/tmp/escape'
            tar.addfile(info,io.BytesIO(b) if info.isfile() else None)


class ArtifactTests(unittest.TestCase):
    def check(self,change=None,extras=(),commit=COMMIT,run=123,digest=None):
        m,files=fixture()
        if change: change(m,files)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bundle.tar.gz'; archive(p,m,files,extras)
            return a.read_archive(p,commit,run,digest)

    def test_valid_bundle(self):
        m,files=self.check(); self.assertEqual(len(files),8); self.assertEqual(m['commit'],COMMIT)

    def test_exact_commit(self):
        with self.assertRaises(ValueError): self.check(commit='b'*40)

    def test_exact_run(self):
        with self.assertRaises(ValueError): self.check(run=124)

    def test_outer_archive_digest(self):
        with self.assertRaises(ValueError): self.check(digest='0'*64)

    def test_payload_tampering(self):
        with self.assertRaises(ValueError): self.check(lambda m,f:f.update({'builds/native/mosdns-c':b'changed'}))

    def test_duplicate_member(self):
        with self.assertRaises(ValueError): self.check(extras=[('builds/native/mosdns-c',b'test-program',None)])

    def test_symlink(self):
        with self.assertRaises(ValueError): self.check(extras=[('escape',b'',tarfile.SYMTYPE)])

    def test_path_traversal(self):
        with self.assertRaises(ValueError): self.check(extras=[('../escape',b'bad',None)])

    def test_unknown_payload(self):
        with self.assertRaises(ValueError): self.check(extras=[('extra',b'bad',None)])

    def test_incomplete_harnesses(self):
        with self.assertRaises(ValueError): self.check(lambda m,f:m['profiles']['native']['tests'].pop('dns_test'))

    # 即使 manifest 中 SHA256 自洽，源码仍必须匹配声明的 Git blob。
    def test_source_commit_blob_tampering(self):
        def change(m,f):
            f['source/main.c']=b'changed'
            m['files']['source/main.c']=dict(bytes=7,sha256=a.digest(b'changed'),mode=0o644)
            m['git_tree']['main.c']=dict(git_blob=a.blob(b'original'),mode=0o644)
        with self.assertRaises(ValueError): self.check(change)

    def test_zip_exact_member(self):
        m,f=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            tar=Path(tmp)/'bundle.tar.gz'; archive(tar,m,f)
            path=Path(tmp)/'artifact.zip'
            with zipfile.ZipFile(path,'w') as z:z.writestr('bundle.tar.gz',tar.read_bytes())
            self.assertEqual(a.read_archive(path,COMMIT,123)[0]['commit'],COMMIT)
            with zipfile.ZipFile(path,'a') as z:z.writestr('../extra',b'bad')
            with self.assertRaises(ValueError):a.read_archive(path,COMMIT,123)


if __name__=='__main__':unittest.main()
