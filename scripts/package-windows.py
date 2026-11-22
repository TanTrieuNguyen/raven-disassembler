"""Build Windows Setup executables from the native, smoke-tested portable packages."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import re
import zipfile

version = re.search(r'^version = "([^"]+)"', Path("Cargo.toml").read_text(), re.M)[1]
compiler = shutil.which("ISCC.exe")
if not compiler:
    compiler = next(
        Path(os.environ["ProgramFiles(x86)"]).glob("Inno Setup */ISCC.exe"), None
    )
if not compiler:
    raise SystemExit("Inno Setup 6.3 or later is required")
incoming, output = map(Path, sys.argv[1:3])
output = output.resolve()
output.mkdir(parents=True, exist_ok=True)

for prefix, allowed in (
    ("i686", "x86compatible"),
    ("x86_64", "x64compatible"),
    ("aarch64", "arm64"),
):
    target = f"{prefix}-pc-windows-msvc"
    package = f"RAVEN-Disassembler-{target}"
    archive = incoming / package / f"{package}.zip"
    with tempfile.TemporaryDirectory(prefix="raven-inno-") as temp:
        stage = Path(temp)
        with zipfile.ZipFile(archive) as source:
            assert source.testzip() is None
            for name in ("raven.exe", "raven-gui.exe", "raven-mcp.exe", "README.md", "LICENSE", "THIRD-PARTY-NOTICES.md", "PLATFORMS.md"):
                (stage / name).write_bytes(source.read(f"{package}/{name}"))
        setup_name = f"{package}-setup"
        script = stage / "raven.iss"
        script.write_text(rf"""[Setup]
AppId=RAVEN-Disassembler-{prefix}
AppName=RAVEN Disassembler
AppVersion={version}
DefaultDirName={{localappdata}}\Programs\RAVEN Disassembler ({prefix})
DefaultGroupName=RAVEN Disassembler ({prefix})
PrivilegesRequired=lowest
MinVersion=10.0
ArchitecturesAllowed={allowed}
UninstallDisplayIcon={{app}}\raven-gui.exe
DisableProgramGroupPage=yes
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "*"; DestDir: "{{app}}"; Excludes: "raven.iss"; Flags: ignoreversion

[Icons]
Name: "{{group}}\RAVEN Disassembler"; Filename: "{{app}}\raven-gui.exe"
""", encoding="utf-8")
        subprocess.run([str(compiler), f"/O{output}", f"/F{setup_name}", str(script)], check=True)
        setup = output / f"{setup_name}.exe"
        if prefix != "aarch64":
            installed = stage / "installed"
            subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/DIR={installed}"], check=True, timeout=120)
            assert (installed / "raven-gui.exe").read_bytes() == (stage / "raven-gui.exe").read_bytes()
            subprocess.run([str(installed / "raven.exe"), "--version"], check=True, timeout=30)
            subprocess.run([str(installed / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], check=True, timeout=120)
        digest = hashlib.sha256(setup.read_bytes()).hexdigest()
        (output / f"{setup.name}.sha256").write_text(f"{digest}  {setup.name}\n")
