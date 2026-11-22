//! Local metadata database. This is not an IDB reader or a remote Teams/Lumina service.
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Annotation {
    pub binary_sha: String,
    pub address: u64,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub author: String,
    pub revision: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub binary_sha: String,
    pub address: u64,
    pub author: String,
    pub revision: u64,
    pub timestamp: u64,
    pub before: Option<Annotation>,
    pub after: Annotation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub architecture: String,
    pub sha256: String,
    pub byte_length: u64,
    pub name: String,
    pub prototype: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnotationBundle {
    pub schema_version: u32,
    pub binary_sha: String,
    pub annotations: Vec<Annotation>,
}

pub struct Store {
    conn: Connection,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn address_key(address: u64) -> String {
    format!("{address:016x}")
}
fn required(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(())
}
fn get_annotation(conn: &Connection, binary_sha: &str, address: u64) -> Result<Option<Annotation>> {
    let row: Option<String> = conn
        .query_row(
            "SELECT document FROM annotations WHERE binary_sha=?1 AND address=?2",
            params![binary_sha, address_key(address)],
            |r| r.get(0),
        )
        .optional()?;
    row.map(|v| serde_json::from_str(&v).context("invalid stored annotation"))
        .transpose()
}

fn annotate_in(
    conn: &Connection,
    binary_sha: &str,
    address: u64,
    name: Option<&str>,
    comment: Option<&str>,
    author: &str,
    expected_revision: Option<u64>,
) -> Result<Annotation> {
    required(binary_sha, "binary_sha")?;
    required(author, "author")?;
    let old = get_annotation(conn, binary_sha, address)?;
    let revision = old.as_ref().map_or(0, |a| a.revision);
    if let Some(expected) = expected_revision {
        if expected != revision {
            bail!("revision conflict at {address:#x}: expected {expected}, current {revision}");
        }
    }
    let next = revision.checked_add(1).context("revision exhausted")?;
    let result = Annotation {
        binary_sha: binary_sha.to_owned(),
        address,
        name: name
            .map(str::to_owned)
            .or_else(|| old.as_ref().and_then(|a| a.name.clone())),
        comment: comment
            .map(str::to_owned)
            .or_else(|| old.as_ref().and_then(|a| a.comment.clone())),
        author: author.to_owned(),
        revision: next,
        updated_at: now()?,
    };
    let document = serde_json::to_string(&result)?;
    conn.execute("INSERT INTO annotations(binary_sha,address,document) VALUES (?1,?2,?3) ON CONFLICT(binary_sha,address) DO UPDATE SET document=excluded.document",
        params![binary_sha, address_key(address), document])?;
    conn.execute("INSERT INTO annotation_events(binary_sha,address,author,revision,timestamp,before_json,after_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![binary_sha, address_key(address), author, i64::try_from(next)?, i64::try_from(result.updated_at)?, old.as_ref().map(serde_json::to_string).transpose()?, document])?;
    Ok(result)
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("open local metadata database")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema_version > 1 {
            bail!("metadata schema {schema_version} is newer than supported version 1");
        }
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS annotations (
                binary_sha TEXT NOT NULL, address TEXT NOT NULL, document TEXT NOT NULL,
                PRIMARY KEY(binary_sha,address));
            CREATE TABLE IF NOT EXISTS annotation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, binary_sha TEXT NOT NULL,
                address TEXT NOT NULL, author TEXT NOT NULL, revision INTEGER NOT NULL,
                timestamp INTEGER NOT NULL, before_json TEXT, after_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_binary ON annotation_events(binary_sha,id);
            CREATE TABLE IF NOT EXISTS signatures (
                architecture TEXT NOT NULL, sha256 TEXT NOT NULL, document TEXT NOT NULL,
                PRIMARY KEY(architecture,sha256));
            PRAGMA user_version=1;",
        )?;
        Ok(Self { conn })
    }

    /// `None` updates atomically without a revision guard; `Some(0)` creates only;
    /// `Some(n)` requires revision n. Omitted name/comment fields preserve old data.
    pub fn annotate(
        &mut self,
        binary_sha: &str,
        address: u64,
        name: Option<&str>,
        comment: Option<&str>,
        author: &str,
        expected_revision: Option<u64>,
    ) -> Result<Annotation> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = annotate_in(
            &tx,
            binary_sha,
            address,
            name,
            comment,
            author,
            expected_revision,
        )?;
        tx.commit()?;
        Ok(result)
    }

    pub fn annotation(&self, binary_sha: &str, address: u64) -> Result<Option<Annotation>> {
        get_annotation(&self.conn, binary_sha, address)
    }

    pub fn annotations(&self, binary_sha: &str) -> Result<Vec<Annotation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT document FROM annotations WHERE binary_sha=?1 ORDER BY address")?;
        let rows = stmt.query_map([binary_sha], |r| r.get::<_, String>(0))?;
        rows.map(|row| serde_json::from_str(&row?).context("decode stored annotation"))
            .collect()
    }

    pub fn events(&self, binary_sha: &str) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare("SELECT id,address,author,revision,timestamp,before_json,after_json FROM annotation_events WHERE binary_sha=?1 ORDER BY id")?;
        let rows = stmt.query_map([binary_sha], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, address, author, revision, timestamp, before, after) = row?;
            Ok(AuditEvent {
                id,
                binary_sha: binary_sha.to_owned(),
                address: u64::from_str_radix(&address, 16)?,
                author,
                revision,
                timestamp,
                before: before.map(|s| serde_json::from_str(&s)).transpose()?,
                after: serde_json::from_str(&after)?,
            })
        })
        .collect()
    }

    pub fn export_annotations(&self, binary_sha: &str) -> Result<String> {
        Ok(serde_json::to_string_pretty(&AnnotationBundle {
            schema_version: 1,
            binary_sha: binary_sha.to_owned(),
            annotations: self.annotations(binary_sha)?,
        })?)
    }

    /// Merge an exported bundle transactionally. Every imported address must have
    /// an explicit expected local revision (0 when absent). Exported revisions are
    /// historical data; successful imports become new local revisions.
    pub fn import_annotations(
        &mut self,
        json: &str,
        author: &str,
        expected_revisions: &BTreeMap<u64, u64>,
    ) -> Result<usize> {
        let bundle: AnnotationBundle = serde_json::from_str(json)?;
        if bundle.schema_version != 1 {
            bail!("unsupported annotation schema {}", bundle.schema_version);
        }
        required(&bundle.binary_sha, "binary_sha")?;
        required(author, "author")?;
        let mut seen = BTreeSet::new();
        for a in &bundle.annotations {
            if a.binary_sha != bundle.binary_sha {
                bail!("bundle contains a different binary identity");
            }
            if !seen.insert(a.address) {
                bail!("duplicate address in bundle: {:#x}", a.address);
            }
            if !expected_revisions.contains_key(&a.address) {
                bail!("missing expected revision for {:#x}", a.address);
            }
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for a in &bundle.annotations {
            annotate_in(
                &tx,
                &bundle.binary_sha,
                a.address,
                a.name.as_deref(),
                a.comment.as_deref(),
                author,
                Some(expected_revisions[&a.address]),
            )?;
        }
        tx.commit()?;
        Ok(bundle.annotations.len())
    }

    pub fn put_signature(
        &self,
        architecture: &str,
        bytes: &[u8],
        name: &str,
        prototype: Option<&str>,
        comment: Option<&str>,
    ) -> Result<Signature> {
        required(architecture, "architecture")?;
        required(name, "name")?;
        if bytes.is_empty() {
            bail!("cannot fingerprint an empty function");
        }
        let value = Signature {
            architecture: architecture.to_owned(),
            sha256: signature_digest(architecture, bytes),
            byte_length: bytes.len() as u64,
            name: name.to_owned(),
            prototype: prototype.map(str::to_owned),
            comment: comment.map(str::to_owned),
        };
        self.conn.execute("INSERT INTO signatures(architecture,sha256,document) VALUES (?1,?2,?3) ON CONFLICT(architecture,sha256) DO UPDATE SET document=excluded.document",
            params![architecture,value.sha256,serde_json::to_string(&value)?])?;
        Ok(value)
    }

    pub fn match_signature(&self, architecture: &str, bytes: &[u8]) -> Result<Option<Signature>> {
        required(architecture, "architecture")?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let row: Option<String> = self
            .conn
            .query_row(
                "SELECT document FROM signatures WHERE architecture=?1 AND sha256=?2",
                params![architecture, signature_digest(architecture, bytes)],
                |r| r.get(0),
            )
            .optional()?;
        row.map(|s| serde_json::from_str(&s).context("decode stored signature"))
            .transpose()
    }
}

/// Domain-separated, architecture-bound exact-byte fingerprint; no relocation normalization.
pub fn signature_digest(architecture: &str, bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"rivet-exact-function-v1\0");
    hash.update((architecture.len() as u64).to_le_bytes());
    hash.update(architecture.as_bytes());
    hash.update(bytes);
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn annotations_roundtrip_revision_and_audit() -> Result<()> {
        let mut s = Store::open(":memory:")?;
        let first = s.annotate(
            "sha",
            u64::MAX,
            Some("entry"),
            Some("first"),
            "alice",
            Some(0),
        )?;
        assert_eq!(first.revision, 1);
        let second = s.annotate("sha", u64::MAX, None, Some("second"), "bob", Some(1))?;
        assert_eq!(second.name.as_deref(), Some("entry"));
        assert_eq!(second.revision, 2);
        assert!(s
            .annotate("sha", u64::MAX, Some("bad"), None, "carol", Some(1))
            .is_err());
        assert_eq!(s.annotations("sha")?, vec![second.clone()]);
        let events = s.events("sha")?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].before, Some(first));
        assert_eq!(events[1].after, second);
        Ok(())
    }
    #[test]
    fn signature_architecture_isolation() -> Result<()> {
        let s = Store::open(":memory:")?;
        let signature = s.put_signature(
            "aarch64",
            &[0xc0, 0x03, 0x5f, 0xd6],
            "return",
            Some("void return(void)"),
            None,
        )?;
        assert_eq!(
            s.match_signature("aarch64", &[0xc0, 0x03, 0x5f, 0xd6])?,
            Some(signature)
        );
        assert_eq!(
            s.match_signature("x86_64", &[0xc0, 0x03, 0x5f, 0xd6])?,
            None
        );
        assert_eq!(
            s.match_signature("aarch64", &[0xc0, 0x03, 0x5f, 0x00])?,
            None
        );
        assert!(s
            .put_signature("aarch64", &[], "empty", None, None)
            .is_err());
        Ok(())
    }
    #[test]
    fn export_import_requires_cas_and_is_atomic() -> Result<()> {
        let mut source = Store::open(":memory:")?;
        source.annotate("sha", 1, Some("a"), None, "alice", Some(0))?;
        source.annotate("sha", 2, Some("b"), None, "alice", Some(0))?;
        let json = source.export_annotations("sha")?;
        let mut destination = Store::open(":memory:")?;
        assert!(destination
            .import_annotations(&json, "bob", &BTreeMap::new())
            .is_err());
        assert!(destination.annotations("sha")?.is_empty());
        destination.annotate("sha", 2, Some("existing"), None, "bob", Some(0))?;
        assert!(destination
            .import_annotations(&json, "bob", &BTreeMap::from([(1, 0), (2, 0)]))
            .is_err());
        assert_eq!(destination.annotations("sha")?.len(), 1);
        assert_eq!(
            destination.import_annotations(&json, "bob", &BTreeMap::from([(1, 0), (2, 1)]))?,
            2
        );
        assert_eq!(destination.annotations("sha")?[1].revision, 2);
        Ok(())
    }
    #[test]
    fn separate_connections_observe_conflicts() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "raven-store-test-{}-{}.sqlite",
            std::process::id(),
            now()?
        ));
        let mut a = Store::open(&path)?;
        let mut b = Store::open(&path)?;
        a.annotate("sha", 0x1234, Some("a"), None, "a", Some(0))?;
        assert!(b
            .annotate("sha", 0x1234, Some("b"), None, "b", Some(0))
            .is_err());
        drop(a);
        drop(b);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
