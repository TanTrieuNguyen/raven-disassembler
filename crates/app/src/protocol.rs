//! MCP stdio JSON-RPC transport. No diagnostic output is written to stdout.
use crate::Workspace;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})
}
pub fn tools() -> Vec<Value> {
    let addr = json!({"type":"string","description":"Virtual address as 0x-prefixed hex or decimal string"});
    let str_ = json!({"type":"string"});
    let size = json!({"type":"integer","minimum":1,"maximum":65536,"description":"Byte length (not instruction count)"});
    let paging = json!({"query":str_,"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":1000}});
    let mut result=vec![
        tool("open_binary","Load a thin ELF, PE or Mach-O file for static analysis. Does not execute it.",json!({"path":str_}),&["path"]),
        tool("close_binary","Release the active binary; SQLite metadata remains.",json!({}),&[]),
        tool("binary_info","Return metadata, analysis inventory and explicit coverage limitations.",json!({}),&[]),
        tool("list_functions","Search symbol/entry/call-target candidate functions, with paging.",paging.clone(),&[]),
        tool("list_strings","Search ASCII strings, with paging.",paging,&[]),
        tool("list_sections","List sections, file mappings and entropy.",json!({}),&[]),
        tool("list_imports","List parsed import declarations.",json!({}),&[]),
        tool("list_exports","List parsed exports.",json!({}),&[]),
        tool("disassemble","Decode real instructions at a virtual address using Capstone.",json!({"address":addr,"size":size}),&["address"]),
        tool("analyze_function","Return inferred function bounds, instructions, basic blocks and direct xrefs. Not decompilation.",json!({"address":addr}),&["address"]),
        tool("xrefs","Return direct control-flow references to an address. Indirect/data references are not recovered.",json!({"address":addr}),&["address"]),
        tool("read_bytes","Read file-backed bytes at a virtual address.",json!({"address":addr,"size":size}),&["address"]),
        tool("annotate","Persist rename/comment and audit event; expected_revision enables conflict detection (0=create).",json!({"address":addr,"name":str_,"comment":str_,"author":str_,"expected_revision":{"type":"integer","minimum":0}}),&["address"]),
        tool("annotations","Read annotations for the active binary hash.",json!({}),&[]),
        tool("audit_log","Read local annotation revision history.",json!({}),&[]),
        tool("export_annotations","Export metadata as a portable JSON document.",json!({}),&[]),
        tool("import_annotations","Atomic import with explicit address-to-revision map. Does not perform Git synchronization.",json!({"document":str_,"author":str_,"revisions":{"type":"object","additionalProperties":{"type":"integer","minimum":0}}}),&["document","revisions"]),
        tool("signature_save","Save exact bytes plus architecture fingerprint in local knowledge database.",json!({"address":addr,"size":size,"name":str_,"prototype":str_,"comment":str_}),&["address","name"]),
        tool("signature_match","Find exact byte and architecture match. Does not ignore relocations.",json!({"address":addr,"size":size}),&["address"]),
        tool("triage","Static IOC candidates, entropy and suspicious string markers. Not a malware verdict.",json!({}),&[]),
        tool("save_report","Write an analysis and annotations report to a selected path.",json!({"path":str_}),&["path"]),
        tool("assist","Send bounded static context to explicitly configured RAVEN_ASSIST_URL. Requires endpoint/model settings.",json!({"question":str_,"address":addr}),&["question"]),
        tool("run_plugin","Execute a caller-selected local process plugin with analysis JSON. Runs with ordinary user permissions.",json!({"manifest":str_}),&["manifest"]),
    ];
    for t in &mut result {
        let write = matches!(
            t["name"].as_str(),
            Some(
                "annotate" | "import_annotations" | "signature_save" | "save_report" | "run_plugin"
            )
        );
        t["annotations"] = json!({"readOnlyHint":!write,"destructiveHint":false,"openWorldHint":matches!(t["name"].as_str(),Some("assist"|"run_plugin"))});
    }
    result
}
pub struct Server {
    pub workspace: Workspace,
    initialized: bool,
}
impl Server {
    pub fn new(workspace: Workspace) -> Self {
        Self {
            workspace,
            initialized: false,
        }
    }
    pub fn handle(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str);
        if request["jsonrpc"] != "2.0" || method.is_none() {
            return Some(error(id.unwrap_or(Value::Null), -32600, "Invalid Request"));
        }
        // Notifications have no response, including unknown methods.
        let id = id?;
        let method = method.unwrap();
        let params = &request["params"];
        let result = match method {
            "initialize" => {
                self.initialized = true;
                let requested = params["protocolVersion"].as_str().unwrap_or("2025-11-25");
                let version = if ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
                    .contains(&requested)
                {
                    requested
                } else {
                    "2025-11-25"
                };
                json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"raven-mcp","version":env!("CARGO_PKG_VERSION")},"instructions":"Independent Rust analysis engine, not Hex-Rays IDA. Inspect limitations before inferring absence. Addresses are virtual; disassembly size is bytes. Annotation storage is shared by database path."})
            }
            "ping" => json!({}),
            _ if !self.initialized => return Some(error(id, -32002, "Initialize first")),
            "tools/list" => json!({"tools":tools()}),
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    return Some(error(id, -32602, "Missing tool name"));
                };
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                if !args.is_object() {
                    return Some(error(id, -32602, "arguments must be an object"));
                }
                if !tools().iter().any(|t| t["name"] == name) {
                    return Some(error(id, -32602, "Unknown tool"));
                }
                match self.workspace.call(name, &args) {
                    Ok(value) => {
                        json!({"content":[{"type":"text","text":serde_json::to_string(&value).unwrap()}],"isError":false})
                    }
                    Err(e) => {
                        json!({"content":[{"type":"text","text":format!("{e:#}")}],"isError":true})
                    }
                }
            }
            _ => return Some(error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
pub fn serve(workspace: Workspace) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let mut server = Server::new(workspace);
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str(&line) {
            Ok(req) => server.handle(req),
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(value) = response {
            serde_json::to_writer(&mut stdout, &value)?;
            writeln!(stdout)?;
            stdout.flush()?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn server() -> Server {
        Server::new(Workspace::new(std::path::Path::new(":memory:")).unwrap())
    }
    #[test]
    fn lifecycle_errors_and_notifications() {
        let mut s = server();
        assert_eq!(
            s.handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
                .unwrap()["error"]["code"],
            -32002
        );
        assert!(s
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .is_none());
        let init=s.handle(json!({"jsonrpc":"2.0","id":"i","method":"initialize","params":{"protocolVersion":"2025-03-26"}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        let unknown = s
            .handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake"}}))
            .unwrap();
        assert_eq!(unknown["error"]["code"], -32602);
        let unopened=s.handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"binary_info"}})).unwrap();
        assert_eq!(unopened["result"]["isError"], true);
        let names: std::collections::BTreeSet<_> = tools()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names.len(), tools().len());
    }
}
