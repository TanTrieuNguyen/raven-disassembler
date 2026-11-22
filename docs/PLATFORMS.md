# Desktop packages

Each archive includes the RAVEN Disassembler GUI, `raven` CLI and `raven-mcp`.

| Package target | Host |
| --- | --- |
| `x86_64-pc-windows-msvc` | Windows 10 or later on x64 |
| `aarch64-pc-windows-msvc` | Windows on ARM64. The build runner is Windows 11 ARM64 |
| `x86_64-unknown-linux-gnu` | Linux x64. Built on Ubuntu 22.04 |
| `aarch64-unknown-linux-gnu` | Linux ARM64. Built on Ubuntu 22.04 |

Extract the archive and run `raven-gui.exe` on Windows or `./raven-gui` on Linux. Pass a file path as the first argument or open it in the GUI. The Linux GUI needs an X11 or Wayland desktop and working system OpenGL libraries. The Linux packages use Ubuntu 22.04 as their build baseline. Older distributions may have incompatible system libraries.

Each host build analyzes x86 (32-bit), x86-64, ARM, Thumb and ARM64 binary code. The host CPU does not have to match the input binary's CPU. The Windows x64 package targets the Windows 10 API baseline, while GitHub's hosted Windows runners exercise newer operating systems. Windows 10 desktop launch coverage requires a separate Windows 10 machine.

Packages and SHA-256 checksums are attached to the **Build desktop packages** workflow run. Download the artifact whose target matches your host.
