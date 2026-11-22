#!/usr/bin/env python3
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
root=Path(__file__).resolve().parent.parent
out=root/'artifacts/RAVEN-Disassembler-source.zip';out.parent.mkdir(exist_ok=True)
include=['Cargo.toml','Cargo.lock','README.md','LICENSE','.gitignore','crates','scripts','docs','fixtures','examples']
with ZipFile(out,'w',ZIP_DEFLATED) as archive:
    for item in include:
        p=root/item
        for f in ([p] if p.is_file() else sorted(p.rglob('*'))):
            if f.is_file() and '__pycache__' not in f.parts:
                archive.write(f,Path('raven-disassembler')/f.relative_to(root))
print(out)
