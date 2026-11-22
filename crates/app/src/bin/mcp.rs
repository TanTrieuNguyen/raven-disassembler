use clap::Parser;
#[derive(Parser)]
#[command(about = "Independent Rust binary-analysis MCP server over stdio")]
struct Args {
    #[arg(long,default_value_os_t=raven::default_database())]
    database: std::path::PathBuf,
    /// Limit this connection to one annotation workspace ID.
    #[arg(long, requires = "shared_author")]
    shared_project: Option<String>,
    /// Fixed author assigned to this annotation connection.
    #[arg(long, requires = "shared_project")]
    shared_author: Option<String>,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let workspace = raven::Workspace::new(&args.database)?;
    if let (Some(project), Some(author)) = (args.shared_project, args.shared_author) {
        let server = raven::protocol::Server::shared(workspace, project, author)?;
        raven::protocol::serve_server(server)
    } else {
        raven::protocol::serve(workspace)
    }
}
