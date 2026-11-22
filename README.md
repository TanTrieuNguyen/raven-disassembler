# RAVEN Disassembler

<img src="crates/app/assets/raven-logo.jpg" alt="RAVEN Disassembler" width="220">

Bàn phân tích binary viết bằng Rust: GUI native, CLI headless, MCP stdio và thư viện dùng chung. Dự án độc lập theo yêu cầu tham chiếu Hex-Rays; **bản 0.1 chưa tương đương đầy đủ IDA Pro hay các add-on**. Xem [bảng tính năng](docs/FEATURE-MATRIX.md) để biết chính xác phần đang chạy và phần còn thiếu.

## Tải app cho Windows và Linux

Tải ZIP Windows hoặc tar.gz Linux trong tab **Actions → Build desktop packages** trên GitHub. Chọn x64 hoặc ARM64 theo CPU của máy chạy. Cả bốn bản phân tích x86-32, x86-64, ARM, Thumb và ARM64. Xem [hướng dẫn nền tảng](docs/PLATFORMS.md).

## Build và chạy

Yêu cầu: Rust stable (đã kiểm chứng với 1.100.0), C/C++ toolchain; macOS cần Xcode Command Line Tools. Dependencies C gồm Capstone và SQLite được build từ crate. Build Windows và Linux chạy trên GitHub Actions.

```sh
cd /absolute/path/to/raven-disassembler
# Toolchain riêng đã cài trong phiên này; không sửa shell profile.
# Nếu giải nén source sang máy khác, dùng Rust đã cài và bỏ dòng source dưới:
. scripts/env.sh
cargo test --workspace
cargo build --release --features gui --bins
./target/release/raven-gui /absolute/path/to/binary
./target/release/raven analyze /absolute/path/to/binary -o analysis.json
./target/release/raven batch file1 file2 -o batch.json
./target/release/raven disasm /absolute/path/to/binary 0x100001000 --size 128
./target/release/raven function /absolute/path/to/binary 0x100001000
./target/release/raven strings /absolute/path/to/binary https
./target/release/raven triage /absolute/path/to/binary
```

Địa chỉ là **virtual address**; `--size` tính bằng byte. Tìm địa chỉ thực từ `analyze` hoặc GUI, không dùng địa chỉ minh họa trên một binary khác. Binary không được thực thi khi phân tích.

GUI: nhập đường dẫn và bấm **Open binary** hoặc kéo file vào cửa sổ. Chọn hàm ở navigator. Disassembly, Control flow, Hex bytes và Inspector dùng chung địa chỉ. Bấm địa chỉ nhảy trong disassembly hoặc tham chiếu trong Inspector để điều hướng. Chọn Pseudocode trong Inspector để xem cạnh disassembly hoặc đồ thị. Dùng **Back** và **Forward** để quay lại. Phím **Space** chuyển giữa disassembly và đồ thị khi ô nhập liệu không có focus. **Save report** ghi `<binary-path>.raven.json`.

## MCP

Ví dụ cấu hình client MCP (thay đường dẫn nếu di chuyển dự án):

```json
{
  "mcpServers": {
    "raven": {
      "command": "/absolute/path/to/raven-disassembler/target/release/raven-mcp"
    }
  }
}
```

Chọn cùng `RAVEN_DB` cho GUI/CLI để chia sẻ annotation. GUI/CLI trên macOS mặc định dùng `~/Library/Application Support/RAVEN Disassembler/workspace.sqlite`; MCP nên dùng đường dẫn tuyệt đối. Server chỉ dùng stdin/stdout cho JSON-RPC, log/lỗi ở stderr. Client gọi `initialize`, rồi `tools/list`, `tools/call`. Đây là MCP riêng của RAVEN, không điều khiển IDA đã cài.

25 tools: `open_binary`, `open_raw`, `close_binary`, `binary_info`, `list_functions`, `list_strings`, `list_sections`, `list_imports`, `list_exports`, `disassemble`, `analyze_function`, `decompile_function`, `xrefs`, `read_bytes`, `annotate`, `annotations`, `audit_log`, `export_annotations`, `import_annotations`, `signature_save`, `signature_match`, `triage`, `save_report`, `assist`, `run_plugin`.

Mọi tool cũng dùng được từ CLI:

```sh
./target/release/raven call --file fixtures/sample list_functions '{"limit":20}'
./target/release/raven call --file fixtures/sample read_bytes '{"address":"0x100000000","size":16}'
```

## Raw binary và pseudocode

```sh
raven raw firmware.bin --mode thumb --base 0x08000000 --disassemble 0x08000000 --size 64
raven decompile file.bin 0x401000
```

Raw loader nhận `x86`, `x86_64`, `arm`, `thumb` hoặc `aarch64`. Dùng `--endian big` cho ảnh ARM phù hợp. Trong GUI, dùng **Tools → open_raw** với các đối số `path`, `mode`, `base`, và `endian` tùy chọn. Metadata của cùng một file raw được tách theo cách ánh xạ.

Pseudocode dùng Ghidra Headless cài riêng. Đặt `RAVEN_GHIDRA_HOME` bằng đường dẫn tuyệt đối tới thư mục Ghidra và dùng JDK mà bản Ghidra yêu cầu. Chọn hàm trong GUI, mở **Pseudocode** và bấm **Decompile selected function**. CLI và MCP dùng cùng adapter. Decompiler phân tích bản sao của binary đang mở và xác định hàm bằng file offset. Chức năng này hỗ trợ binary định dạng ELF, PE hoặc Mach-O mà Ghidra import được.

## Metadata, chữ ký hàm và trao đổi

```sh
raven --database workspace.sqlite annotate file.bin 0x401000 --name parse_header --comment 'checked header' --author analyst --expected-revision 0
raven --database workspace.sqlite call --file file.bin annotations '{}'
raven --database workspace.sqlite call --file file.bin signature_save '{"address":"0x401000","size":32,"name":"parse_header"}'
```

Tên tool trong `call` dùng underscore: `signature_save`, với `{"address":"0x401000","size":32,"name":"parse_header"}`. `signature_match` cần cùng kích thước byte. Chữ ký hiện khớp chính xác bytes + architecture, chưa bỏ qua relocation.

Annotation có revision. `expected_revision:0` tạo mới; revision hiện tại dùng để sửa. Không khớp sẽ báo conflict và giữ dữ liệu cũ. CLI/MCP có thể bỏ expected revision để cập nhật vô điều kiện; GUI luôn dùng revision. `import_annotations` yêu cầu map revision cho tất cả địa chỉ trong document; import là một transaction. JSON export có thể đưa vào Git bằng công cụ Git của bạn; chưa có đồng bộ Git/remote tự động.

## Assist

Cấu hình endpoint chat-completions tương thích (có thể là model local):

```sh
export RAVEN_ASSIST_URL=http://127.0.0.1:1234/v1/chat/completions
export RAVEN_ASSIST_MODEL=my-local-model
# Nếu endpoint cần token, đặt RAVEN_ASSIST_KEY trong môi trường.
raven assist file.bin 'Explain this function' --address 0x401000
```

Chỉ lệnh Assist gửi tối đa khoảng 48KB ngữ cảnh phân tích đến endpoint đã chọn. Không tự sửa annotation, không chạy tool do model đề xuất. Phần kết nối được kiểm thử bằng mock local; chưa kiểm thử model thật. Không có endpoint/model thì báo cấu hình thiếu, không tạo câu trả lời giả.

## Plugin SDK

Tạo manifest có đường dẫn tuyệt đối:

```json
{"name":"section-stats","version":"1.0.0","executable":"/usr/bin/python3","args":["/absolute/path/to/raven-disassembler/examples/plugin.py"],"description":"Summarize executable sections"}
```

```sh
raven call --file file.bin run_plugin '{"manifest":"/absolute/path/to/plugin.json"}'
```

Plugin nhận một JSON analysis qua stdin và trả một JSON qua stdout; stderr dành cho log. Thời hạn direct process 30 giây, output tối đa 4MiB mỗi stream. Plugin là chương trình thật chạy với quyền user, không có sandbox và không tương thích ABI plugin IDA. Thư viện Rust public nằm trong `crates/core` và `crates/addons`.

## Kiểm chứng và tài liệu

- [Phạm vi so với tất cả mục trong ảnh](docs/FEATURE-MATRIX.md)
- [Kết quả kiểm chứng](docs/VALIDATION.md)
- [Thiết kế và roadmap](docs/ARCHITECTURE.md)
- [Kho SQLite](crates/addons/README.md)

Tên sản phẩm Hex-Rays dùng để đối chiếu phạm vi. RAVEN không chứa logo, license hay mã proprietary của Hex-Rays.
