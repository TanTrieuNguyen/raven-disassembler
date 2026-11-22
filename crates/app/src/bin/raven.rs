use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use raven::{parse_address, Workspace};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
#[derive(Parser)]
#[command(
    version,
    about = "RAVEN Disassembler — independent Rust binary analysis workbench"
)]
struct Args {
    #[arg(long,global=true,default_value_os_t=raven::default_database())]
    database: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    /// Inventory and analyze a file. No execution.
    Analyze {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Analyze many files independently; failed files remain in the result.
    Batch {
        files: Vec<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decode instructions; addresses are virtual, size is bytes.
    Disasm {
        file: PathBuf,
        address: String,
        #[arg(long, default_value_t = 256)]
        size: usize,
    },
    Function {
        file: PathBuf,
        address: String,
    },
    Strings {
        file: PathBuf,
        #[arg(default_value = "")]
        query: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Triage {
        file: PathBuf,
    },
    Annotate {
        file: PathBuf,
        address: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long, default_value = "local")]
        author: String,
        #[arg(long)]
        expected_revision: Option<u64>,
    },
    /// All shared engine/tools are available by name with JSON arguments.
    Call {
        #[arg(long)]
        file: Option<PathBuf>,
        tool: String,
        #[arg(default_value = "{}")]
        arguments: String,
    },
    /// Print the real tool SDK schemas.
    Tools,
    /// Start MCP stdio transport.
    Mcp,
    /// Send selected static context to a configured chat-completions endpoint.
    Assist {
        file: PathBuf,
        question: String,
        #[arg(long)]
        address: Option<String>,
    },
}
fn write(value: Value, output: Option<PathBuf>) -> Result<()> {
    let text = serde_json::to_string_pretty(&value)?;
    if let Some(path) = output {
        fs::write(path, text)?;
    } else {
        println!("{text}");
    }
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(args.command, Cmd::Tools) {
        return write(json!(raven::protocol::tools()), None);
    }
    let mut w = Workspace::new(&args.database)?;
    if matches!(args.command, Cmd::Mcp) {
        return raven::protocol::serve(w);
    }
    let open = |w: &mut Workspace, path: &PathBuf| -> Result<Value> {
        w.call(
            "open_binary",
            &json!({"path":path.to_str().context("file path must be UTF-8")?}),
        )
    };
    let (result, output) = match args.command {
        Cmd::Analyze { file, output } => (open(&mut w, &file)?, output),
        Cmd::Batch { files, output } => {
            anyhow::ensure!(!files.is_empty(), "provide at least one file");
            let rows: Vec<_> = files
                .iter()
                .map(|file| match open(&mut w, file) {
                    Ok(v) => json!({"file":file,"ok":true,"analysis":v}),
                    Err(e) => json!({"file":file,"ok":false,"error":format!("{e:#}")}),
                })
                .collect();
            (json!({"results":rows}), output)
        }
        Cmd::Disasm {
            file,
            address,
            size,
        } => {
            open(&mut w, &file)?;
            (
                w.call(
                    "disassemble",
                    &json!({"address":parse_address(&address)?,"size":size}),
                )?,
                None,
            )
        }
        Cmd::Function { file, address } => {
            open(&mut w, &file)?;
            (
                w.call(
                    "analyze_function",
                    &json!({"address":parse_address(&address)?}),
                )?,
                None,
            )
        }
        Cmd::Strings { file, query, limit } => {
            open(&mut w, &file)?;
            (
                w.call("list_strings", &json!({"query":query,"limit":limit}))?,
                None,
            )
        }
        Cmd::Triage { file } => (raven::extras::triage(&file)?, None),
        Cmd::Annotate {
            file,
            address,
            name,
            comment,
            author,
            expected_revision,
        } => {
            open(&mut w, &file)?;
            {
                let mut args = json!({"address":parse_address(&address)?,"name":name,"comment":comment,"author":author});
                if let Some(revision) = expected_revision {
                    args["expected_revision"] = json!(revision);
                }
                (w.call("annotate", &args)?, None)
            }
        }
        Cmd::Call {
            file,
            tool,
            arguments,
        } => {
            if let Some(file) = file {
                open(&mut w, &file)?;
            }
            let arguments: Value =
                serde_json::from_str(&arguments).context("arguments must be JSON")?;
            (w.call(&tool, &arguments)?, None)
        }
        Cmd::Assist {
            file,
            question,
            address,
        } => {
            open(&mut w, &file)?;
            let mut a = json!({"question":question});
            if let Some(address) = address {
                a["address"] = json!(parse_address(&address)?);
            }
            (w.call("assist", &a)?, None)
        }
        Cmd::Mcp | Cmd::Tools => unreachable!(),
    };
    write(result, output)
}
