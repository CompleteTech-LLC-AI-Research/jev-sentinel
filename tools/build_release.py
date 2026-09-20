"""Build a reproducible source ZIP and a self-contained Python installer."""
from __future__ import annotations
import argparse
import base64
import hashlib
from pathlib import Path
import textwrap
import zipfile

ROOT=Path(__file__).resolve().parents[1]
STANDALONE='''#!/usr/bin/env python3
"""Self-contained JEV Sentinel installer. Default: preview; --apply writes settings.

Embedded package SHA-256: __SHA__
No network fetch. Python 3.10+ required. Review source/SECURITY.md before deployment.
"""
from __future__ import annotations
import base64
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import zipfile
PAYLOAD = (
__PAYLOAD__
)
SHA256 = "__SHA__"

def main():
    if sys.version_info < (3,10):
        raise SystemExit('Python 3.10+ is required.')
    raw = base64.b85decode(PAYLOAD)
    if len(raw) > 16_000_000 or hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit('Embedded package integrity check failed.')
    # Only temporary extraction occurs in plan mode; no harness settings change.
    with tempfile.TemporaryDirectory(prefix='jev-sentinel-', dir=os.environ.get('JEV_SENTINEL_TMPDIR')) as directory:
        root = Path(directory)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if sum(item.file_size for item in archive.infolist()) > 32_000_000:
                raise SystemExit('Embedded archive size limit exceeded.')
            for item in archive.infolist():
                rel = PurePosixPath(item.filename)
                if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] != 'jev-sentinel':
                    raise SystemExit('Unsafe archive path.')
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise SystemExit('Archive symlink refused.')
                dest = root.joinpath(*rel.parts)
                if item.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with dest.open('xb') as stream:
                        stream.write(archive.read(item))
        return subprocess.call([sys.executable, '-I', str(root/'jev-sentinel/install.py'), *sys.argv[1:]])

if __name__ == '__main__':
    raise SystemExit(main())
'''

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--out',type=Path,default=ROOT.parent)
    args=p.parse_args()
    out=args.out.resolve()
    if ROOT==out or ROOT in out.parents:
        raise SystemExit('Release output must be outside the source tree.')
    out.mkdir(parents=True,exist_ok=True)
    dest=out/'jev-sentinel-0.1.0.zip'
    with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for file in sorted(ROOT.rglob('*')):
            rel=file.relative_to(ROOT)
            if any(part == '.env' or (part.startswith('.env.') and part != '.env.example') for part in rel.parts):
                continue
            if not file.is_file() or any(part in ('__pycache__','.git') for part in rel.parts) or file.suffix=='.pyc':
                continue
            if file.is_symlink():
                raise SystemExit('Source symlink refused.')
            info=zipfile.ZipInfo('jev-sentinel/'+rel.as_posix(),(2026,9,19,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(0o100644 << 16)
            z.writestr(info,file.read_bytes())
    payload=dest.read_bytes()
    digest=hashlib.sha256(payload).hexdigest()
    chunks=textwrap.wrap(base64.b85encode(payload).decode(),100,break_on_hyphens=False)
    literal='\n'.join('    '+repr(chunk.encode()) for chunk in chunks)
    script=out/'install_jev_sentinel.py'
    script.write_text(STANDALONE.replace('__PAYLOAD__',literal).replace('__SHA__',digest),encoding='utf-8')
    artifacts=[dest,script]
    sums=''.join(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.name+'\n' for file in artifacts)
    (out/'jev-sentinel-SHA256SUMS.txt').write_text(sums,encoding='utf-8')
    print(sums,end='')

if __name__=='__main__':main()
