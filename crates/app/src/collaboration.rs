//! Annotation endpoint intended for authenticated stdio transports such as SSH.
use crate::{address, text, Workspace};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

pub(crate) struct Project {
    key: String,
    author: String,
}

impl Project {
    pub(crate) fn new(key: String, author: String) -> Result<Self> {
        ensure!(
            key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "shared project must be a 64-character workspace SHA-256"
        );
        ensure!(
            !author.trim().is_empty()
                && author.len() <= 120
                && !author.chars().any(char::is_control),
            "invalid shared author"
        );
        Ok(Self {
            key: key.to_ascii_lowercase(),
            author,
        })
    }

    pub(crate) fn tools(&self) -> Vec<Value> {
        let mut tools: Vec<_> = crate::protocol::tools()
            .into_iter()
            .filter(|tool| {
                matches!(
                    tool["name"].as_str(),
                    Some("annotate" | "annotations" | "audit_log" | "export_annotations")
                )
            })
            .collect();
        for tool in &mut tools {
            if tool["name"] == "annotate" {
                tool["description"] = json!("Write an annotation to the bound workspace. Supply the last observed revision, or zero for a new address.");
                tool["inputSchema"]["properties"]
                    .as_object_mut()
                    .expect("annotate schema")
                    .remove("author");
                tool["inputSchema"]["required"] = json!(["address", "expected_revision"]);
            }
        }
        tools.push(json!({
            "name":"project_info", "description":"Identify the bound shared project and server-configured author.",
            "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
            "annotations":{"readOnlyHint":true}
        }));
        tools
    }

    pub(crate) fn call(
        &self,
        workspace: &mut Workspace,
        name: &str,
        args: &Value,
    ) -> Result<Value> {
        let object = args.as_object().context("arguments must be an object")?;
        if name != "annotate" {
            ensure!(object.is_empty(), "this tool does not take arguments");
        }
        match name {
            "project_info" => Ok(json!({"workspace_id":self.key,"author":self.author})),
            "annotations" => Ok(serde_json::to_value(
                workspace.store.annotations(&self.key)?,
            )?),
            "audit_log" => Ok(serde_json::to_value(workspace.store.events(&self.key)?)?),
            "export_annotations" => Ok(serde_json::from_str(
                &workspace.store.export_annotations(&self.key)?,
            )?),
            "annotate" => {
                ensure!(
                    object.keys().all(|key| matches!(
                        key.as_str(),
                        "address" | "name" | "comment" | "expected_revision"
                    )),
                    "unsupported annotation argument; author is configured by the host"
                );
                let revision = args["expected_revision"]
                    .as_u64()
                    .context("expected_revision is required")?;
                let name = args.get("name").map(|_| text(args, "name")).transpose()?;
                let comment = args
                    .get("comment")
                    .map(|_| text(args, "comment"))
                    .transpose()?;
                ensure!(
                    name.is_some() || comment.is_some(),
                    "supply name, comment, or both"
                );
                ensure!(
                    name.is_none_or(|name| name.len() <= 512)
                        && comment.is_none_or(|comment| comment.len() <= 8192),
                    "annotation exceeds the shared field size limit"
                );
                let annotation = workspace.store.annotate(
                    &self.key,
                    address(args, "address")?,
                    name,
                    comment,
                    &self.author,
                    Some(revision),
                )?;
                Ok(serde_json::to_value(annotation)?)
            }
            _ => bail!("tool unavailable in annotation-only mode"),
        }
    }
}
