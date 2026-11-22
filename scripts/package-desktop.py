"""Validate an on-host release build and package GUI, CLI and MCP for distribution."""
import hashlib
import json
import pathlib
import shutil
import tempfile
import re
import subprocess
import sys
import tarfile
import zipfile

root = pathlib.Path(__file__).resolve().parent.parent
target = sys.argv[1]
windows = "windows" in target
macos = target.endswith("apple-darwin")
version = re.search(r'^version = "([^"]+)"', (root / "Cargo.toml").read_text(), re.M)[1]
suffix = ".exe" if windows else ""
release = root / "target" / target / "release"
executables = [release / (name + suffix) for name in ("raven", "raven-gui", "raven-mcp")]
cli, _, mcp = executables
analysis = json.loads(subprocess.check_output(
    [str(cli), "--database", ":memory:", "analyze", str(cli)], timeout=180))
expected_arch = target.split("-", 1)[0].replace("i686", "x86")
if analysis["architecture"] != expected_arch:
    raise RuntimeError(f"expected {expected_arch}, received {analysis['architecture']}")
expected_format = "Pe" if windows else "MachO" if macos else "Elf"
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
if macos:
    archive = out / f"{name}.dmg"
    with tempfile.TemporaryDirectory(prefix="raven-dmg-") as temporary:
        volume = pathlib.Path(temporary)
        contents = volume / "RAVEN Disassembler.app" / "Contents"
        binaries = contents / "MacOS"
        resources = contents / "Resources"
        binaries.mkdir(parents=True)
        resources.mkdir()
        for executable in executables:
            shutil.copy2(executable, binaries)
        for document in files[3:]:
            shutil.copy2(document, resources)
        subprocess.run(["sips", "-s", "format", "icns", "-z", "512", "512",
                        str(root / "crates/app/assets/raven-logo.jpg"),
                        "--out", str(resources / "Raven.icns")], check=True)
        import plistlib
        (contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "dev.raven.disassembler", "CFBundleName": "RAVEN Disassembler",
            "CFBundleExecutable": "raven-gui", "CFBundleIconFile": "Raven.icns",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": version,
            "CFBundleVersion": version, "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        }))
        app = contents.parent
        for executable in executables:
            subprocess.run(["codesign", "--force", "--sign", "-", str(binaries / executable.name)], check=True)
        subprocess.run(["codesign", "--force", "--sign", "-", str(app)], check=True)
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
        (volume / "Applications").symlink_to("/Applications", target_is_directory=True)
        subprocess.run(["hdiutil", "create", "-ov", "-fs", "HFS+", "-format", "UDZO",
                        "-volname", "RAVEN Disassembler", "-srcfolder", str(volume), str(archive)], check=True)
        subprocess.run(["hdiutil", "verify", str(archive)], check=True)
elif windows:
    archive = out / f"{name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        for file in files:
            package.write(file, f"{name}/{file.name}")
else:
    archive = out / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for file in files:
            package.add(file, arcname=f"{name}/{file.name}")
packages = [archive]
if not windows and not macos:
    architecture = {"x86": "i386", "x86_64": "amd64", "aarch64": "arm64"}[expected_arch]
    deb = out / f"{name}.deb"
    with tempfile.TemporaryDirectory(prefix="raven-deb-") as temporary:
        staging = pathlib.Path(temporary)
        for name_ in ("DEBIAN", "usr/bin", "usr/share/applications", "usr/share/doc/raven-disassembler"):
            (staging / name_).mkdir(parents=True)
        (staging / "DEBIAN/control").write_text(
            f"Package: raven-disassembler\nVersion: {version}\nArchitecture: {architecture}\n"
            "Maintainer: RAVEN Disassembler contributors\nSection: devel\nPriority: optional\n"
            "Depends: libc6 (>= 2.35), libgl1, libx11-6, libwayland-client0, libxkbcommon0\n"
            "Description: Native binary analysis workbench and MCP server\n"
        )
        (staging / "usr/share/applications/raven-disassembler.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=RAVEN Disassembler\nExec=/usr/bin/raven-gui %f\n"
            "Terminal=false\nCategories=Development;\n"
        )
        for executable in executables:
            shutil.copy2(executable, staging / "usr/bin")
        for document in files[3:]:
            shutil.copy2(document, staging / "usr/share/doc/raven-disassembler")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(staging), str(deb)], check=True)
        assert subprocess.check_output(["dpkg-deb", "-f", str(deb), "Architecture"], text=True).strip() == architecture
    packages.append(deb)

for package in packages:
    checksum = hashlib.sha256(package.read_bytes()).hexdigest()
    (out / f"{package.name}.sha256").write_text(f"{checksum}  {package.name}\n")
    print(f"{checksum}  {package.name}")
