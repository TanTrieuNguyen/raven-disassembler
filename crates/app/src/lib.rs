pub mod extras;
pub mod protocol;
use anyhow::{bail, Context, Result};
use raven_core::Analysis;
use raven_store::Store;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub fn parse_address(value: &str) -> Result<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}
pub fn address(args: &Value, key: &str) -> Result<u64> {
    if let Some(n) = args[key].as_u64() {
        return Ok(n);
    }
    parse_address(
        args[key]
            .as_str()
            .with_context(|| format!("{key}: expected hex address string or unsigned number"))?,
    )
}
pub fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key]
        .as_str()
        .with_context(|| format!("{key}: expected string"))
}
pub fn default_database() -> PathBuf {
    if let Some(path) = std::env::var_os("RAVEN_DB").or_else(|| std::env::var_os("RIVET_DB")) {
        return path.into();
    }
    if let Some(root) = std::env::var_os("HOME") {
        let path = PathBuf::from(root);
        let (current, previous) = if cfg!(target_os = "macos") {
            (
                "Library/Application Support/RAVEN Disassembler/workspace.sqlite",
                "Library/Application Support/Rivet RE/workspace.sqlite",
            )
        } else {
            (
                ".local/share/raven-disassembler/workspace.sqlite",
                ".local/share/rivet-re/workspace.sqlite",
            )
        };
        let current = path.join(current);
        let previous = path.join(previous);
        return if !current.exists() && previous.is_file() {
            previous
        } else {
            current
        };
    }
    PathBuf::from("raven.sqlite")
}
pub struct Workspace {
    pub analysis: Option<Analysis>,
    pub store: Store,
}
impl Workspace {
    pub fn new(db: &Path) -> Result<Self> {
        if let Some(parent) = db.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            analysis: None,
            store: Store::open(db)?,
        })
    }
    pub fn a(&self) -> Result<&Analysis> {
        self.analysis.as_ref().context("open a binary first")
    }
    pub fn call(&mut self, name: &str, args: &Value) -> Result<Value> {
        if !args.is_object() {
            bail!("arguments must be an object");
        }
        if let Some(revision) = args.get("expected_revision") {
            if revision.as_u64().is_none() {
                bail!("expected_revision must be unsigned");
            }
        }
        if let Some(offset) = args.get("offset") {
            if offset.as_u64().is_none() {
                bail!("offset must be unsigned");
            }
        }
        if let Some(query) = args.get("query") {
            if !query.is_string() {
                bail!("query must be a string");
            }
        }
        match name {
            "open_binary" => {
                let analysis = Analysis::open(Path::new(text(args, "path")?))?;
                let value = serde_json::to_value(&analysis)?;
                self.analysis = Some(analysis);
                Ok(value)
            }
            "close_binary" => {
                self.analysis = None;
                Ok(json!({"closed":true}))
            }
            "binary_info" => Ok(serde_json::to_value(self.a()?)?),
            "list_functions" => {
                let a = self.a()?;
                let q = args["query"].as_str().unwrap_or("");
                let renamed: BTreeMap<_, _> = self
                    .store
                    .annotations(&a.sha256)?
                    .into_iter()
                    .filter_map(|ann| ann.name.map(|name| (ann.address, name)))
                    .collect();
                let all = a
                    .functions
                    .iter()
                    .cloned()
                    .map(|mut f| {
                        if let Some(name) = renamed.get(&f.address) {
                            f.name = name.clone();
                        }
                        f
                    })
                    .filter(|f| f.name.contains(q))
                    .collect::<Vec<_>>();
                page(all, args)
            }
            "list_strings" => {
                let a = self.a()?;
                let q = args["query"].as_str().unwrap_or("");
                let all = a
                    .strings
                    .iter()
                    .filter(|s| s.value.contains(q))
                    .collect::<Vec<_>>();
                page(all, args)
            }
            "list_sections" => Ok(serde_json::to_value(&self.a()?.sections)?),
            "list_imports" => Ok(serde_json::to_value(&self.a()?.imports)?),
            "list_exports" => Ok(serde_json::to_value(&self.a()?.exports)?),
            "disassemble" => Ok(serde_json::to_value(self.a()?.disassemble(
                address(args, "address")?,
                bounded(args, "size", 256, 65536)?,
            )?)?),
            "analyze_function" => {
                let a = self.a()?;
                let address = address(args, "address")?;
                let mut detail = a.function(address)?;
                if let Some(name) = self
                    .store
                    .annotation(&a.sha256, address)?
                    .and_then(|ann| ann.name)
                {
                    detail.function.name = name;
                }
                Ok(serde_json::to_value(detail)?)
            }
            "xrefs" => Ok(serde_json::to_value(
                self.a()?.xrefs(address(args, "address")?),
            )?),
            "read_bytes" => {
                let bytes = self
                    .a()?
                    .read_bytes(address(args, "address")?, bounded(args, "size", 64, 65536)?)?;
                Ok(json!({"hex":hex::encode(bytes)}))
            }
            "annotate" => {
                let sha = self.a()?.sha256.clone();
                let addr = address(args, "address")?;
                let author = args["author"].as_str().unwrap_or("local");
                let ann = self.store.annotate(
                    &sha,
                    addr,
                    args["name"].as_str(),
                    args["comment"].as_str(),
                    author,
                    args["expected_revision"].as_u64(),
                )?;
                Ok(serde_json::to_value(ann)?)
            }
            "annotations" => Ok(serde_json::to_value(
                self.store.annotations(&self.a()?.sha256)?,
            )?),
            "audit_log" => Ok(serde_json::to_value(self.store.events(&self.a()?.sha256)?)?),
            "export_annotations" => Ok(serde_json::from_str(
                &self.store.export_annotations(&self.a()?.sha256)?,
            )?),
            "import_annotations" => {
                let document = text(args, "document")?;
                // Each address must have a caller-provided expected revision; no silent merge.
                let revisions = args["revisions"]
                    .as_object()
                    .context("revisions must map address strings to expected revisions")?;
                let mut expected = BTreeMap::new();
                for (addr, rev) in revisions {
                    expected.insert(
                        parse_address(addr)?,
                        rev.as_u64().context("revision must be unsigned")?,
                    );
                }
                let imported = self.store.import_annotations(
                    document,
                    args["author"].as_str().unwrap_or("local"),
                    &expected,
                )?;
                Ok(json!({"imported":imported}))
            }
            "signature_save" => {
                let a = self.a()?;
                let bytes =
                    a.read_bytes(address(args, "address")?, bounded(args, "size", 32, 65536)?)?;
                Ok(serde_json::to_value(self.store.put_signature(
                    &a.architecture,
                    &bytes,
                    text(args, "name")?,
                    args["prototype"].as_str(),
                    args["comment"].as_str(),
                )?)?)
            }
            "signature_match" => {
                let a = self.a()?;
                let bytes =
                    a.read_bytes(address(args, "address")?, bounded(args, "size", 32, 65536)?)?;
                Ok(
                    json!({"match":self.store.match_signature(&a.architecture,&bytes)?,"method":"architecture + exact byte SHA-256; not relocation invariant"}),
                )
            }
            "triage" => extras::triage(Path::new(&self.a()?.path)),
            "save_report" => {
                let path = Path::new(text(args, "path")?);
                let report = json!({"schemaVersion":1,"analysis":self.a()?,"annotations":self.store.annotations(&self.a()?.sha256)?});
                fs::write(path, serde_json::to_vec_pretty(&report)?)?;
                Ok(json!({"saved":path}))
            }
            "assist" => {
                let context = if !args["address"].is_null() {
                    serde_json::to_value(self.a()?.function(address(args, "address")?)?)?
                } else {
                    serde_json::to_value(self.a()?)?
                };
                extras::assist(text(args, "question")?, &context)
            }
            "run_plugin" => extras::run_plugin(
                Path::new(text(args, "manifest")?),
                &serde_json::to_value(self.a()?)?,
            ),
            _ => bail!("unknown tool: {name}"),
        }
    }
}
fn bounded(args: &Value, key: &str, default: usize, max: usize) -> Result<usize> {
    let n = match args.get(key) {
        None => default,
        Some(v) => v.as_u64().context("size must be an unsigned integer")? as usize,
    };
    if n == 0 || n > max {
        bail!("{key} must be 1..={max}");
    }
    Ok(n)
}
fn page<T: serde::Serialize>(all: Vec<T>, args: &Value) -> Result<Value> {
    let offset = args["offset"].as_u64().unwrap_or(0) as usize;
    let limit = bounded(args, "limit", 100, 1000)?;
    let total = all.len();
    let end = offset.saturating_add(limit).min(total);
    let rows: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
    Ok(
        json!({"total":total,"offset":offset,"next_offset":if end<total{Some(end)}else{None},"items":rows}),
    )
}
