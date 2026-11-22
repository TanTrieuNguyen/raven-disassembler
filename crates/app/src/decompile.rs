use anyhow::{bail, ensure, Context, Result};
use raven_core::Analysis;
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn function(analysis: &Analysis, address: u64) -> Result<Value> {
    ensure!(
        analysis
            .functions
            .iter()
            .any(|function| function.address == address),
        "no function seed at {address:#x}"
    );
    let offset = analysis.file_offset(address)?;
    let ghidra = PathBuf::from(
        std::env::var_os("RAVEN_GHIDRA_HOME")
            .context("set RAVEN_GHIDRA_HOME to a Ghidra installation")?,
    );
    ensure!(
        ghidra.is_absolute(),
        "RAVEN_GHIDRA_HOME must be an absolute path"
    );
    let launcher = ghidra.join("support").join(if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    });
    ensure!(
        launcher.is_file(),
        "Ghidra headless launcher not found: {}",
        launcher.display()
    );

    let work = tempfile::Builder::new().prefix("raven-ghidra-").tempdir()?;
    let input = work.path().join("input.bin");
    let output = work.path().join("pseudocode.c");
    let mapped_address = work.path().join("address.txt");
    let log_path = work.path().join("headless.log");
    fs::write(&input, analysis.snapshot())?;
    fs::write(
        work.path().join("RavenDecompile.java"),
        include_str!("ghidra/RavenDecompile.java"),
    )?;
    let log = File::create(&log_path)?;
    let mut child = Command::new(launcher)
        .arg(work.path())
        .arg("raven")
        .arg("-import")
        .arg(&input)
        .args(["-analysisTimeoutPerFile", "120", "-scriptPath"])
        .arg(work.path())
        .args(["-postScript", "RavenDecompile.java", &offset.to_string()])
        .arg(&output)
        .arg(&mapped_address)
        .arg("-deleteProject")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .context("launch Ghidra headless")?;
    let deadline = Instant::now() + Duration::from_secs(240);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                outcome.context("wait for Ghidra headless")?;
                bail!("Ghidra headless exceeded 240 seconds");
            }
        }
    };
    if !status.success() || !output.is_file() {
        let mut file = File::open(&log_path)?;
        let end = file.metadata()?.len();
        file.seek(SeekFrom::Start(end.saturating_sub(4096)))?;
        let mut tail = Vec::new();
        file.take(4096).read_to_end(&mut tail)?;
        bail!(
            "Ghidra returned no pseudocode ({status}): {}",
            String::from_utf8_lossy(&tail)
        );
    }
    ensure!(
        output.metadata()?.len() <= 1024 * 1024,
        "pseudocode exceeds 1 MiB"
    );
    Ok(json!({
        "provider": "Ghidra headless",
        "sha256": analysis.sha256,
        "address": format!("{address:#x}"),
        "file_offset": offset,
        "provider_address": fs::read_to_string(mapped_address)?,
        "language": "C",
        "pseudocode": fs::read_to_string(output)?,
        "limitations": ["Pseudocode is inferred from static analysis. Types and names may differ from the original source."]
    }))
}
