# Desktop installation

Download the asset that matches the architecture of the operating system on which RAVEN will run. The installer includes the GUI, `raven` CLI and `raven-mcp`. The analyzed file may use a different CPU architecture.

| Host | CPU | Installation |
| --- | --- | --- |
| Windows 10 or later | x86, x64 | Run the matching Setup executable. A portable ZIP is also available. |
| Windows 11 | ARM64 | Run the ARM64 Setup executable or extract the portable ZIP. |
| macOS 11 or later | Intel x64, Apple Silicon ARM64 | Open the DMG and copy RAVEN Disassembler to Applications. |
| Ubuntu 22.04 or compatible Debian-based systems | x86, x64, ARM64 | Run `sudo apt install ./<downloaded-file>.deb`. |
| Other compatible Linux systems | x86, x64, ARM64 | Extract the tar.gz and run `raven-gui`. |

The macOS application is ad-hoc signed and not notarized. On a trusted downloaded copy, use the standard macOS Privacy & Security approval if Gatekeeper blocks it. Windows installers are unsigned. Compare the downloaded file with the release SHA-256 checksums before installing.

Linux builds use Ubuntu 22.04 as their build baseline. The GUI requires X11 or Wayland and system OpenGL libraries. Linux x86 binaries are built and smoke-tested on a 64-bit Ubuntu runner with the 32-bit runtime. Windows x86 binaries are smoke-tested under the Windows 32-bit compatibility layer. Hosted build and smoke tests do not replace an interactive desktop session on each operating system release.

Build from source with stable Rust, a C/C++ compiler and the following platform dependencies:

- Windows: the MSVC toolchain and Windows SDK for the selected CPU.
- macOS: Xcode Command Line Tools.
- Linux: Mesa OpenGL, xkbcommon, Wayland, X11, XInput, Xcursor, Xrandr, Xinerama and D-Bus development packages.
