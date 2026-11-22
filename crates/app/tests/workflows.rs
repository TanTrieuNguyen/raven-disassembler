use anyhow::Result;
use raven::{protocol::Server, Workspace};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const ENTRY: u64 = 0x401000;
const HELPER: u64 = ENTRY + 6;
const CODE: &[u8] = &[0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    binary: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "raven-workflow-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory)?;
        let binary = directory.join("sample.elf");
        let database = directory.join("metadata.sqlite");
        fs::write(&binary, elf_fixture())?;
        Ok(Self {
            directory,
            binary,
            database,
        })
    }
    fn workspace(&self) -> Result<Workspace> {
        let mut workspace = Workspace::new(&self.database)?;
        workspace.call("open_binary", &json!({"path":self.binary}))?;
        Ok(workspace)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// A complete, small ELF fixture with two named functions and a known direct call.
/// No compiler, external fixture, or host architecture dependency is needed.
fn elf_fixture() -> Vec<u8> {
    fn u16_(b: &mut [u8], p: usize, v: u16) {
        b[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn u32_(b: &mut [u8], p: usize, v: u32) {
        b[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn u64_(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    // Fixture writer takes one argument per ELF64 section header field.
    #[allow(clippy::too_many_arguments)]
    fn section(
        b: &mut [u8],
        index: usize,
        name: u32,
        kind: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: u64,
    ) {
        let p = 0x300 + index * 64;
        u32_(b, p, name);
        u32_(b, p + 4, kind);
        u64_(b, p + 8, flags);
        u64_(b, p + 16, address);
        u64_(b, p + 24, offset);
        u64_(b, p + 32, size);
        u32_(b, p + 40, link);
        u32_(b, p + 44, info);
        u64_(b, p + 48, alignment);
        u64_(b, p + 56, entry_size);
    }
    let mut b = vec![0; 0x440];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    u16_(&mut b, 16, 2);
    u16_(&mut b, 18, 62);
    u32_(&mut b, 20, 1);
    u64_(&mut b, 24, ENTRY);
    u64_(&mut b, 40, 0x300);
    u16_(&mut b, 52, 64);
    u16_(&mut b, 58, 64);
    u16_(&mut b, 60, 5);
    u16_(&mut b, 62, 2);
    b[0x80..0x80 + CODE.len()].copy_from_slice(CODE);
    let section_names = b"\0.text\0.shstrtab\0.symtab\0.strtab\0";
    b[0xa0..0xa0 + section_names.len()].copy_from_slice(section_names);
    let names = b"\0entry\0helper\0";
    b[0x260..0x260 + names.len()].copy_from_slice(names);
    for (index, name, address) in [(1, 1, ENTRY), (2, 7, HELPER)] {
        let p = 0x200 + index * 24;
        u32_(&mut b, p, name);
        b[p + 4] = 0x12;
        u16_(&mut b, p + 6, 1);
        u64_(&mut b, p + 8, address);
        u64_(&mut b, p + 16, 6);
    }
    section(
        &mut b,
        1,
        1,
        1,
        6,
        ENTRY,
        0x80,
        CODE.len() as u64,
        0,
        0,
        16,
        0,
    );
    section(
        &mut b,
        2,
        7,
        3,
        0,
        0,
        0xa0,
        section_names.len() as u64,
        0,
        0,
        1,
        0,
    );
    section(&mut b, 3, 17, 2, 0, 0, 0x200, 72, 4, 1, 8, 24);
    section(
        &mut b,
        4,
        25,
        3,
        0,
        0,
        0x260,
        names.len() as u64,
        0,
        0,
        1,
        0,
    );
    b
}

#[test]
fn binary_analysis_metadata_and_report_workflow() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut workspace = fixture.workspace()?;
    let info = workspace.call("binary_info", &json!({}))?;
    assert_eq!(info["format"], "Elf");
    assert_eq!(info["architecture"], "x86_64");
    assert_eq!(info["entry"], ENTRY);
    assert_eq!(info["sha256"].as_str().unwrap().len(), 64);
    assert!(!info["limitations"].as_array().unwrap().is_empty());

    let functions = workspace.call("list_functions", &json!({"query":"helper","limit":1}))?;
    assert_eq!(functions["total"], 1);
    assert_eq!(functions["items"][0]["address"], HELPER);
    let bytes = workspace.call("read_bytes", &json!({"address":"0x401000","size":12}))?;
    assert_eq!(bytes["hex"], hex::encode(CODE));
    let disassembly = workspace.call("disassemble", &json!({"address":ENTRY,"size":6}))?;
    assert_eq!(disassembly[0]["mnemonic"], "call");
    assert_eq!(disassembly[0]["target"], HELPER);
    assert_eq!(disassembly[1]["mnemonic"], "ret");
    let function = workspace.call("analyze_function", &json!({"address":ENTRY}))?;
    assert_eq!(function["function"]["name"], "entry");
    assert!(!function["blocks"].as_array().unwrap().is_empty());
    let references = workspace.call("xrefs", &json!({"address":HELPER}))?;
    assert!(references
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["from"] == ENTRY && r["kind"] == "call"));

    let first = workspace.call("annotate",&json!({"address":HELPER,"name":"answer","comment":"returns 42","author":"test","expected_revision":0}))?;
    assert_eq!(first["revision"], 1);
    let second = workspace.call("annotate",&json!({"address":HELPER,"comment":"verified fixture","author":"reviewer","expected_revision":1}))?;
    assert_eq!(second["name"], "answer");
    assert_eq!(second["revision"], 2);
    assert_eq!(
        workspace.call("analyze_function", &json!({"address":HELPER}))?["function"]["name"],
        "answer"
    );
    let renamed = workspace.call("list_functions", &json!({"query":"answer"}))?;
    assert_eq!(renamed["total"], 1);
    assert_eq!(renamed["items"][0]["address"], HELPER);
    assert!(workspace
        .call(
            "annotate",
            &json!({"address":HELPER,"name":"stale","expected_revision":1})
        )
        .is_err());
    assert_eq!(
        workspace
            .call("audit_log", &json!({}))?
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let saved = workspace.call(
        "signature_save",
        &json!({"address":HELPER,"size":6,"name":"answer","prototype":"int answer(void)"}),
    )?;
    assert_eq!(saved["name"], "answer");
    assert_eq!(
        workspace.call("signature_match", &json!({"address":HELPER,"size":6}))?["match"]["name"],
        "answer"
    );
    assert_eq!(
        workspace.call("signature_match", &json!({"address":ENTRY,"size":6}))?["match"],
        Value::Null
    );

    let report_path = fixture.directory.join("report.json");
    workspace.call("save_report", &json!({"path":report_path}))?;
    let report: Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    assert_eq!(report["analysis"]["sha256"], info["sha256"]);
    assert_eq!(report["annotations"][0]["revision"], 2);
    let exported = workspace.call("export_annotations", &json!({}))?;
    let document = serde_json::to_string(&exported)?;
    let mut imported = Workspace::new(&fixture.directory.join("imported.sqlite"))?;
    imported.call("open_binary", &json!({"path":fixture.binary}))?;
    assert!(imported
        .call(
            "import_annotations",
            &json!({"document":document,"revisions":{}})
        )
        .is_err());
    let revisions = json!({"0x401006":0});
    assert_eq!(
        imported.call(
            "import_annotations",
            &json!({"document":document,"author":"importer","revisions":revisions})
        )?["imported"],
        1
    );
    assert_eq!(
        imported.call("annotations", &json!({}))?[0]["name"],
        "answer"
    );
    assert!(imported
        .call(
            "import_annotations",
            &json!({"document":document,"revisions":revisions})
        )
        .is_err());
    drop(imported);
    workspace.call("close_binary", &json!({}))?;
    assert!(workspace.call("binary_info", &json!({})).is_err());
    drop(workspace);
    let mut reopened = fixture.workspace()?;
    assert_eq!(
        reopened.call("annotations", &json!({}))?[0]["name"],
        "answer"
    );
    assert_eq!(
        reopened.call("signature_match", &json!({"address":HELPER,"size":6}))?["match"]["name"],
        "answer"
    );
    Ok(())
}

#[test]
fn rejects_malformed_sizes_addresses_and_unsupported_inputs() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut workspace = fixture.workspace()?;
    let original_identity = workspace.call("binary_info", &json!({}))?["sha256"].clone();
    let unsupported = fixture.directory.join("malformed.bin");
    fs::write(&unsupported, b"not an executable")?;
    assert!(workspace
        .call("open_binary", &json!({"path":unsupported}))
        .is_err());
    assert_eq!(
        workspace.call("binary_info", &json!({}))?["sha256"],
        original_identity
    );
    for size in [
        json!(0),
        json!(-1),
        json!(65537),
        json!("8"),
        Value::Null,
        json!(1.5),
    ] {
        assert!(
            workspace
                .call("read_bytes", &json!({"address":ENTRY,"size":size}))
                .is_err(),
            "accepted size {size}"
        );
        assert!(
            workspace
                .call("disassemble", &json!({"address":ENTRY,"size":size}))
                .is_err(),
            "accepted size {size}"
        );
    }
    for address in [
        json!(-1),
        json!(true),
        json!(1.5),
        json!("0xno"),
        json!("18446744073709551616"),
        Value::Null,
    ] {
        assert!(
            workspace
                .call("read_bytes", &json!({"address":address,"size":1}))
                .is_err(),
            "accepted address {address}"
        );
    }
    assert!(workspace
        .call(
            "read_bytes",
            &json!({"address":"0xffffffffffffffff","size":1})
        )
        .is_err());
    assert!(workspace
        .call("list_functions", &json!({"limit":1001}))
        .is_err());
    for revision in [json!(-1), json!("0"), json!(1.5), Value::Null] {
        assert!(
            workspace
                .call(
                    "annotate",
                    &json!({"address":HELPER,"name":"invalid","expected_revision":revision})
                )
                .is_err(),
            "accepted revision {revision}"
        );
    }
    Ok(())
}

#[test]
fn mcp_dispatch_returns_analysis_and_tool_errors() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut server = Server::new(Workspace::new(&fixture.database)?);
    assert!(server
        .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .is_none());
    let init=server.handle(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}})).unwrap();
    assert!(init["result"]["capabilities"]["tools"].is_object());
    let opened=server.handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":fixture.binary}}})).unwrap();
    assert_eq!(opened["result"]["isError"], false);
    let function=server.handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_function","arguments":{"address":"0x401006"}}})).unwrap();
    let detail: Value =
        serde_json::from_str(function["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(detail["function"]["name"], "helper");
    let invalid=server.handle(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_bytes","arguments":{"address":"0x401000","size":0}}})).unwrap();
    assert_eq!(invalid["result"]["isError"], true);
    let unknown=server.handle(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"unregistered_tool"}})).unwrap();
    assert_eq!(unknown["error"]["code"], -32602);
    Ok(())
}

#[test]
fn mcp_stdio_roundtrip_has_only_jsonrpc_on_stdout() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_raven-mcp"))
        .env("RAVEN_DB", &fixture.database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().unwrap();
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":fixture.binary}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_bytes","arguments":{"address":"0x401006","size":6}}}),
    ] {
        serde_json::to_writer(&mut input, &request)?;
        writeln!(input)?;
    }
    drop(input);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses: Vec<Value> = String::from_utf8(output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(responses.len(), 3);
    assert!(responses.iter().all(|r| r["jsonrpc"] == "2.0"));
    assert_eq!(responses[2]["id"], 3);
    let bytes: Value = serde_json::from_str(
        responses[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )?;
    assert_eq!(bytes["hex"], "b82a000000c3");
    Ok(())
}

#[test]
fn raw_thumb_uses_explicit_mapping_and_separates_annotations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("thumb.bin");
    std::fs::write(&path, [0x70, 0x47]).unwrap(); // bx lr
    let mut workspace = Workspace::new(dir.path().join("workspace.sqlite").as_path()).unwrap();
    let open = |workspace: &mut Workspace, base: &str| {
        workspace.call("open_raw", &json!({"path":path,"mode":"thumb","base":base}))
    };
    let first = open(&mut workspace, "0x1000").unwrap();
    let detail = workspace
        .call("analyze_function", &json!({"address":"0x1000"}))
        .unwrap();
    assert_eq!(detail["instructions"][0]["mnemonic"], "bx");
    assert_eq!(detail["instructions"][0]["flow"], "return");
    assert_eq!(workspace.a().unwrap().file_offset(0x1000).unwrap(), 0);
    workspace
        .call(
            "annotate",
            &json!({"address":"0x1000","name":"first_mapping"}),
        )
        .unwrap();
    assert!(open(&mut workspace, "0x2001").is_err());
    assert_eq!(workspace.a().unwrap().entry, 0x1000);
    let second = open(&mut workspace, "0x2000").unwrap();
    assert_eq!(first["sha256"], second["sha256"]);
    assert_ne!(
        first["raw_mapping"]["workspace_id"],
        second["raw_mapping"]["workspace_id"]
    );
    assert_eq!(
        workspace.call("annotations", &json!({})).unwrap(),
        json!([])
    );
}

#[test]
fn native_lifter_and_xrefs_use_typed_operands() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("flat.bin");
    let mut image = vec![0x90; 40];
    // mov eax,edi; add eax,esi; ret
    image[..5].copy_from_slice(&[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    // call [rip+0x0a], using the fixed pointer at 0x1020.
    image[16..22].copy_from_slice(&[0xff, 0x15, 0x0a, 0, 0, 0]);
    image[22] = 0xc3;
    image[32..40].copy_from_slice(&0x1000u64.to_le_bytes());
    std::fs::write(&file, image).unwrap();
    let mut workspace = Workspace::new(std::path::Path::new(":memory:")).unwrap();
    workspace
        .call(
            "open_raw",
            &json!({"path":file,"mode":"x86_64","base":"0x1000"}),
        )
        .unwrap();
    let result = workspace
        .call(
            "emulate_function",
            &json!({
                "address":"0x1000","arguments":["0xffffffff",2]
            }),
        )
        .unwrap();
    assert_eq!(result["return_value"], "0x1");
    assert_eq!(result["argument_widths"], json!([32, 32]));
    assert_eq!(
        result["prototype"],
        "uint32_t raven_function(uint32_t arg0, uint32_t arg1)"
    );
    let outgoing = workspace
        .call("xrefs", &json!({"address":"0x1010","direction":"outgoing"}))
        .unwrap();
    assert!(outgoing
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["to"] == 0x1020 && item["kind"] == "data-read"));
    assert!(outgoing
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["to"] == 0x1000 && item["kind"] == "indirect-call-candidate"));
    let disasm = workspace
        .call("disassemble", &json!({"address":"0x1010","size":6}))
        .unwrap();
    assert!(disasm[0]["target"].is_null());
}

#[test]
fn shared_annotations_use_host_author_and_revisions_across_connections() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("shared.sqlite");
    let key = "ab".repeat(32);
    fn client(db: &std::path::Path, key: &str, author: &str) -> Server {
        let mut server = Server::shared(
            Workspace::new(db).unwrap(),
            key.to_owned(),
            author.to_owned(),
        )
        .unwrap();
        server
            .handle(json!({"jsonrpc":"2.0","method":"initialize","id":1}))
            .unwrap();
        server
    }
    fn call(server: &mut Server, method: &str, arguments: Value) -> Value {
        server
            .handle(json!({"jsonrpc":"2.0","method":"tools/call","id":2,
            "params":{"name":method,"arguments":arguments}}))
            .unwrap()
    }
    let mut alice = client(&db, &key, "Alice");
    let mut bob = client(&db, &key, "Bob");
    let first = call(
        &mut alice,
        "annotate",
        json!({"address":"0x1000","name":"sum","expected_revision":0}),
    );
    assert_eq!(first["result"]["isError"], false);
    let list = call(&mut bob, "annotations", json!({}));
    let annotations: Value =
        serde_json::from_str(list["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(annotations[0]["author"], "Alice");
    let conflict = call(
        &mut bob,
        "annotate",
        json!({"address":"0x1000","comment":"stale","expected_revision":0}),
    );
    assert_eq!(conflict["result"]["isError"], true);
    let forged = call(
        &mut bob,
        "annotate",
        json!({"address":"0x1000","name":"forged","expected_revision":1,"author":"Alice"}),
    );
    assert_eq!(forged["result"]["isError"], true);
    let next = call(
        &mut bob,
        "annotate",
        json!({"address":"0x1000","comment":"reviewed","expected_revision":1}),
    );
    assert_eq!(next["result"]["isError"], false);
    let forbidden = call(&mut bob, "open_binary", json!({"path":"/etc/passwd"}));
    assert_eq!(forbidden["error"]["code"], -32602);
}
