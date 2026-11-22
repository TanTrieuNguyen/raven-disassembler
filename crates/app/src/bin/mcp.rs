use clap::Parser;
#[derive(Parser)]
#[command(about = "Independent Rust binary-analysis MCP server over stdio")]
struct Args {
    #[arg(long,default_value_os_t=raven::default_database())]
    database: std::path::PathBuf,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    raven::protocol::serve(raven::Workspace::new(&args.database)?)
}
