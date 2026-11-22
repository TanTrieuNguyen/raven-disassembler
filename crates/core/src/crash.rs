//! Postmortem state from Linux ELF core notes. No program is run or attached.
use super::read_input;
use anyhow::{bail, ensure, Result};
use object::{elf, read::elf::ProgramHeader, Architecture, File, Object, ObjectKind};
use serde_json::{json, Value};
use std::path::Path;

const PRSTATUS_REGISTERS: usize = 112; // LP64 Linux elf_prstatus.pr_reg byte offset.

pub fn inspect_core(path: impl AsRef<Path>) -> Result<Value> {
    let bytes = read_input(path.as_ref())?;
    parse_core(&bytes)
}

fn parse_core(bytes: &[u8]) -> Result<Value> {
    let File::Elf64(file) = File::parse(bytes)? else {
        bail!("expected a Linux ELF64 core dump");
    };
    ensure!(
        file.kind() == ObjectKind::Core,
        "ELF input is not a core dump"
    );
    let (pc_slot, sp_slot, register_end, architecture) = match file.architecture() {
        Architecture::X86_64 => (16, 19, 27, "x86_64"),
        Architecture::Aarch64 => (32, 31, 34, "aarch64"),
        _ => bail!("core register decoding supports Linux x86-64 and ARM64"),
    };
    let endian = file.endian();
    let mut threads = Vec::new();
    let mut rejected_notes = 0usize;
    let mut truncated = false;
    'segments: for header in file.elf_program_headers() {
        let Some(mut notes) = header.notes(endian, file.data())? else {
            continue;
        };
        while let Some(note) = notes.next()? {
            if note.name() != b"CORE" || note.n_type(endian) != elf::NT_PRSTATUS {
                continue;
            }
            let desc = note.desc();
            if desc.len() < PRSTATUS_REGISTERS + register_end * 8 {
                rejected_notes += 1;
                continue;
            }
            if threads.len() >= 4096 {
                truncated = true;
                break 'segments;
            }
            let read_u16 = |offset| {
                let data: [u8; 2] = desc[offset..offset + 2].try_into().expect("checked layout");
                if file.is_little_endian() {
                    u16::from_le_bytes(data)
                } else {
                    u16::from_be_bytes(data)
                }
            };
            let read_u32 = |offset| {
                let data: [u8; 4] = desc[offset..offset + 4].try_into().expect("checked layout");
                if file.is_little_endian() {
                    u32::from_le_bytes(data)
                } else {
                    u32::from_be_bytes(data)
                }
            };
            let read_reg = |slot: usize| {
                let offset = PRSTATUS_REGISTERS + slot * 8;
                let data: [u8; 8] = desc[offset..offset + 8].try_into().expect("checked layout");
                if file.is_little_endian() {
                    u64::from_le_bytes(data)
                } else {
                    u64::from_be_bytes(data)
                }
            };
            threads.push(json!({
                "thread_id": read_u32(32),
                "current_signal": read_u16(12),
                "pc": format!("{:#x}", read_reg(pc_slot)),
                "sp": format!("{:#x}", read_reg(sp_slot))
            }));
        }
    }
    Ok(json!({
        "format": "Linux ELF64 core",
        "architecture": architecture,
        "threads": threads,
        "rejected_prstatus_notes": rejected_notes,
        "truncated": truncated,
        "limitations": ["Recorded thread PC, SP and signal only. No process attachment, live execution, symbolization, or stack unwinding."]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_linux_prstatus_and_ignores_truncated_descriptor() {
        let mut bytes = vec![0u8; 496];
        let u16 = |bytes: &mut [u8], at, value: u16| {
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes())
        };
        let u32 = |bytes: &mut [u8], at, value: u32| {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes())
        };
        let u64 = |bytes: &mut [u8], at, value: u64| {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes())
        };
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        u16(&mut bytes, 16, elf::ET_CORE);
        u16(&mut bytes, 18, elf::EM_X86_64);
        u32(&mut bytes, 20, 1);
        u64(&mut bytes, 32, 64);
        u16(&mut bytes, 52, 64);
        u16(&mut bytes, 54, 56);
        u16(&mut bytes, 56, 1);
        u32(&mut bytes, 64, elf::PT_NOTE);
        u64(&mut bytes, 72, 120);
        u64(&mut bytes, 96, 376);
        u64(&mut bytes, 112, 4);
        u32(&mut bytes, 120, 5);
        u32(&mut bytes, 124, 336);
        u32(&mut bytes, 128, elf::NT_PRSTATUS);
        bytes[132..137].copy_from_slice(b"CORE\0");
        u16(&mut bytes, 152, 11);
        u32(&mut bytes, 172, 42);
        u64(&mut bytes, 380, 0x401000);
        u64(&mut bytes, 404, 0x7fff1000);
        u32(&mut bytes, 476, 5);
        u32(&mut bytes, 484, elf::NT_PRSTATUS);
        bytes[488..493].copy_from_slice(b"CORE\0");
        let report = parse_core(&bytes).unwrap();
        assert_eq!(
            report["threads"][0],
            json!({"thread_id":42,"current_signal":11,"pc":"0x401000","sp":"0x7fff1000"})
        );
        assert_eq!(report["rejected_prstatus_notes"], 1);
    }
}
