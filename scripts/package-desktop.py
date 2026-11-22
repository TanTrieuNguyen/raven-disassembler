"""Validate an on-host release build and package GUI, CLI and MCP for distribution."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import zipfile

root = pathlib.Path(__file__).resolve().parent.parent
target = sys.argv[1]
windows = "windows" in target
suffix = ".exe" if windows else ""
release = root / "target" / target / "release"
executables = [release / (name + suffix) for name in ("raven", "raven-gui", "raven-mcp")]
cli, _, mcp = executables
analysis = json.loads(subprocess.check_output(
    [str(cli), "--database", ":memory:", "analyze", str(cli)], timeout=180))
expected_arch = target.split("-", 1)[0]
if analysis["architecture"] != expected_arch:
    raise RuntimeError(f"expected {expected_arch}, received {analysis['architecture']}")
expected_format = "Pe" if windows else "Elf"
if analysis["format"] != expected_format:
    raise RuntimeError(f"expected {expected_format}, received {analysis['format']}")
requests = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-11-25"}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]
response = subprocess.run(
    [str(mcp), "--database", ":memory:"],
    input="".join(json.dumps(item) + "\n" for item in requests),
    capture_output=True, text=True, check=True, timeout=30)
initialized, discovered = map(json.loads, response.stdout.splitlines())
assert initialized["result"]["serverInfo"]["name"] == "raven-mcp"
assert any(tool["name"] == "disassemble" for tool in discovered["result"]["tools"])

out = root / "artifacts"
out.mkdir(exist_ok=True)
name = f"RAVEN-Disassembler-{target}"
files = [*executables, root / "README.md", root / "LICENSE",
         root / "docs" / "THIRD-PARTY-NOTICES.md", root / "docs" / "PLATFORMS.md"]
if windows:
    archive = out / f"{name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        for file in files:
            package.write(file, f"{name}/{file.name}")
else:
    archive = out / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for file in files:
            package.add(file, arcname=f"{name}/{file.name}")
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
(out / f"{archive.name}.sha256").write_text(f"{checksum}  {archive.name}\n")
print(f"{checksum}  {archive.name}")
