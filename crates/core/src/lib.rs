//! Independent binary analysis. Addresses are virtual addresses, never file offsets.
use anyhow::{anyhow, bail, Context, Result};
use capstone::{arch, prelude::*};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};

pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISASSEMBLY_BYTES: usize = 65536;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub executable: bool,
    pub entropy: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub kind: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub library: String,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub address: u64,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryString {
    pub file_offset: u64,
    pub address: Option<u64>,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub target: Option<u64>,
    pub flow: String,
}
impl Instruction {
    pub fn end(&self) -> u64 {
        self.address.saturating_add((self.bytes.len() / 2) as u64)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub address: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDetail {
    pub function: Function,
    pub instructions: Vec<Instruction>,
    pub xrefs: Vec<Xref>,
    pub blocks: Vec<BasicBlock>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub path: String,
    pub sha256: String,
    pub format: String,
    pub architecture: String,
    pub entry: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_mapping: Option<RawMapping>,
    pub sections: Vec<Section>,
    pub functions: Vec<Function>,
    pub symbols: Vec<Symbol>,
    pub strings: Vec<BinaryString>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub limitations: Vec<String>,
    #[serde(skip)]
    bytes: Vec<u8>,
    #[serde(skip)]
    references: Vec<Xref>,
    #[serde(skip)]
    little_endian: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawMapping {
    pub base: u64,
    pub mode: String,
    pub little_endian: bool,
    pub workspace_id: String,
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    anyhow::ensure!(
        std::fs::metadata(path)?.is_file(),
        "input must be a regular file"
    );
    let file = std::fs::File::open(path).context("open binary")?;
    let metadata = file.metadata().context("reading binary metadata")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        bail!("input must be a regular file <=512 MiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_FILE_BYTES,
        "input exceeds 512 MiB"
    );
    Ok(bytes)
}

pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / bytes.len() as f64;
            -p * p.log2()
        })
        .sum()
}

impl Analysis {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::from_bytes(path.to_string_lossy().into_owned(), read_input(path)?)
    }

    pub fn open_raw(
        path: impl AsRef<Path>,
        mode: &str,
        base: u64,
        little_endian: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        let (architecture, alignment) = match mode {
            "x86" | "x86_64" => {
                anyhow::ensure!(little_endian, "x86 requires little endian");
                (mode, 1)
            }
            "arm" | "aarch64" => (mode, 4),
            "thumb" => ("arm", 2),
            _ => bail!("raw mode must be x86, x86_64, arm, thumb or aarch64"),
        };
        anyhow::ensure!(
            base.is_multiple_of(alignment),
            "base must be aligned to {alignment} bytes"
        );
        let bytes = read_input(path)?;
        let size = bytes.len() as u64;
        anyhow::ensure!(size != 0, "empty raw image");
        let last = base
            .checked_add(size)
            .and_then(|end| end.checked_sub(1))
            .context("raw mapping overflows virtual addresses")?;
        if matches!(architecture, "x86" | "arm") {
            anyhow::ensure!(
                last <= u64::from(u32::MAX),
                "raw mapping exceeds 32-bit address space"
            );
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let workspace_id = hex::encode(Sha256::digest(format!(
            "raven-raw-v1:{sha256}:{mode}:{base}:{little_endian}"
        )));
        let sections = vec![Section {
            name: "raw".into(),
            address: base,
            size,
            file_offset: 0,
            file_size: size,
            executable: true,
            entropy: entropy(&bytes),
        }];
        let strings = ascii_strings(&bytes, &sections);
        let seed = Function {
            address: base,
            name: "entry".into(),
            size: 0,
            source: "raw-base".into(),
        };
        let analysis = Self {
            path: path.to_string_lossy().into_owned(), sha256, format: "Raw".into(),
            architecture: architecture.into(), entry: base,
            raw_mapping: Some(RawMapping { base, mode: mode.into(), little_endian, workspace_id }),
            sections, functions: vec![], symbols: vec![], imports: vec![], exports: vec![],
            strings, bytes, references: vec![], little_endian,
            limitations: vec!["The entire raw image is treated as potential code. Base, architecture, and endianness are caller-selected and there are no format-derived function boundaries.".into(),
                "Direct references and CFG are inferred from a bounded linear sweep. Indirect references and data layout are unknown.".into()],
        };
        Ok(analysis.finish(BTreeMap::from([(base, seed)])))
    }

    pub fn workspace_id(&self) -> &str {
        self.raw_mapping
            .as_ref()
            .map_or(&self.sha256, |mapping| &mapping.workspace_id)
    }

    pub fn from_bytes(path: String, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() as u64 > MAX_FILE_BYTES {
            bail!("input exceeds 512 MiB");
        }
        let file = object::File::parse(bytes.as_slice()).context(
            "unsupported or malformed object; choose a thin ELF, PE/COFF, or Mach-O file",
        )?;
        let architecture = match file.architecture() {
            object::Architecture::X86_64 => "x86_64",
            object::Architecture::I386 => "x86",
            object::Architecture::Aarch64 => "aarch64",
            object::Architecture::Arm => "arm",
            _ => "unsupported",
        }
        .to_owned();
        let sections: Vec<_> = file
            .sections()
            .map(|s| {
                let (offset, size) = s.file_range().unwrap_or((0, 0));
                Section {
                    name: s.name().unwrap_or("<invalid-name>").to_owned(),
                    address: s.address(),
                    size: s.size(),
                    file_offset: offset,
                    file_size: size,
                    executable: s.kind() == SectionKind::Text,
                    entropy: entropy(s.data().unwrap_or_default()),
                }
            })
            .collect();
        let symbols: Vec<_> = file
            .symbols()
            .chain(file.dynamic_symbols())
            .filter_map(|s| {
                let name = s.name().ok()?.to_owned();
                if name.is_empty() || s.is_undefined() {
                    return None;
                }
                Some(Symbol {
                    address: s.address(),
                    name,
                    size: s.size(),
                    kind: format!("{:?}", s.kind()),
                })
            })
            .collect();
        let mut seeds: BTreeMap<u64, Function> = BTreeMap::new();
        for s in file.symbols().chain(file.dynamic_symbols()) {
            if s.kind() == SymbolKind::Text
                && !s.is_undefined()
                && sections.iter().any(|section| {
                    section.executable
                        && contains(
                            section.address,
                            section.file_size,
                            if architecture == "arm" {
                                s.address() & !1
                            } else {
                                s.address()
                            },
                        )
                })
            {
                if let Ok(name) = s.name() {
                    if !name.is_empty() {
                        seeds.entry(s.address()).or_insert(Function {
                            address: s.address(),
                            name: name.to_owned(),
                            size: s.size(),
                            source: "symbol".into(),
                        });
                    }
                }
            }
        }
        let raw_entry = file.entry();
        // object 0.36 returns Mach-O LC_MAIN entryoff (a file offset), unlike ELF/PE VAs.
        let entry = if file.format() == object::BinaryFormat::MachO && raw_entry != 0 {
            sections
                .iter()
                .find(|s| s.executable && contains(s.file_offset, s.file_size, raw_entry))
                .and_then(|s| s.address.checked_add(raw_entry - s.file_offset))
                .unwrap_or(0)
        } else {
            raw_entry
        };
        if entry != 0
            && sections
                .iter()
                .any(|s| s.executable && contains(s.address, s.file_size, entry))
        {
            seeds.entry(entry).or_insert(Function {
                address: entry,
                name: "entry".into(),
                size: 0,
                source: "entry-point".into(),
            });
        }
        let import_result = file.imports();
        let import_error = import_result.as_ref().err().map(|e| e.to_string());
        let imports = import_result
            .unwrap_or_default()
            .into_iter()
            .map(|i| Import {
                library: String::from_utf8_lossy(i.library()).into_owned(),
                name: String::from_utf8_lossy(i.name()).into_owned(),
            })
            .collect();
        let export_result = file.exports();
        let export_error = export_result.as_ref().err().map(|e| e.to_string());
        let exports = export_result
            .unwrap_or_default()
            .into_iter()
            .map(|e| Export {
                address: e.address(),
                name: String::from_utf8_lossy(e.name()).into_owned(),
            })
            .collect();
        let strings = ascii_strings(&bytes, &sections);
        let little_endian = file.is_little_endian();
        let format = format!("{:?}", file.format());
        drop(file);
        let mut result = Self { path, sha256: hex::encode(Sha256::digest(&bytes)), format, architecture, entry, raw_mapping: None,
            sections, functions: vec![], symbols, strings, imports, exports,
            limitations: vec!["Function seeds use symbols, entry point and direct calls; stripped/indirect functions may be missing.".into(),
                "References cover direct code branches/calls only; data and indirect references are unknown.".into(),
                "Automatic executable-section linear sweep can misidentify embedded data as code; call-derived seeds are inferred.".into(),
                "ASCII strings only (minimum four bytes, maximum 200000 results).".into(),
                "CFG models recognized branch/call/return instructions; exception edges and unresolved indirect destinations are unknown.".into()], bytes, references: vec![], little_endian };
        if let Some(error) = import_error {
            result
                .limitations
                .push(format!("Import table unavailable: {error}"));
        }
        if let Some(error) = export_error {
            result
                .limitations
                .push(format!("Export table unavailable: {error}"));
        }
        if result.architecture == "arm" {
            result.limitations.push("Automatic scan uses ARM mode. For Thumb disassembly pass address with low bit set; automatic Thumb references are incomplete.".into());
        }
        if raw_entry != 0 && entry == 0 {
            result.limitations.push(format!("Mach-O entry file offset 0x{raw_entry:x} could not be mapped; entry virtual address is unknown (reported as zero)."));
        }
        Ok(result.finish(seeds))
    }

    fn finish(mut self, mut seeds: BTreeMap<u64, Function>) -> Self {
        let result = &mut self;
        let mut scan_left = MAX_SCAN_BYTES;
        for s in result.sections.clone().into_iter().filter(|s| s.executable) {
            let count = (s.file_size as usize).min(scan_left);
            if count == 0 {
                continue;
            }
            scan_left -= count;
            // Decode one contiguous region, preserving variable-length instruction boundaries.
            match result.decode(s.address, count, false) {
                Ok(insns) => {
                    let decoded_bytes = insns.iter().map(|i| i.bytes.len() / 2).sum::<usize>();
                    if decoded_bytes < count {
                        result.limitations.push(format!("Direct-reference scan for section {} decoded {decoded_bytes} of {count} requested bytes; trailing bytes remain unknown.", s.name));
                    }
                    if insns.iter().any(|i| i.flow == "data") {
                        result.limitations.push(format!("Section {} contains undecodable bytes marked as data; CFG does not infer flow across them.",s.name));
                    }
                    for i in insns {
                        if let Some(target) = i.target {
                            result.references.push(Xref {
                                from: i.address,
                                to: target,
                                kind: i.flow.clone(),
                            });
                            if i.flow == "call"
                                && result.sections.iter().any(|s| {
                                    s.executable
                                        && contains(
                                            s.address,
                                            s.file_size,
                                            if result.architecture == "arm" {
                                                target & !1
                                            } else {
                                                target
                                            },
                                        )
                                })
                            {
                                seeds.entry(target).or_insert(Function {
                                    address: target,
                                    name: format!("sub_{target:x}"),
                                    size: 0,
                                    source: "direct-call".into(),
                                });
                            }
                        }
                    }
                }
                Err(error) => result.limitations.push(format!(
                    "Direct-reference scan for section {} unavailable: {error}",
                    s.name
                )),
            }
        }
        if result
            .sections
            .iter()
            .filter(|s| s.executable)
            .map(|s| s.file_size)
            .fold(0u64, u64::saturating_add)
            > MAX_SCAN_BYTES as u64
        {
            result.limitations.push("Automatic direct-reference scan limited to first 2 MiB of executable section bytes.".into());
        }
        if result.architecture == "unsupported" {
            result
                .limitations
                .push("Architecture can be inventoried but has no configured disassembler.".into());
        }
        result.functions = seeds.into_values().collect();
        for index in 0..result.functions.len() {
            let f = result.functions[index].clone();
            if f.size != 0 {
                continue;
            }
            let start = if result.architecture == "arm" {
                f.address & !1
            } else {
                f.address
            };
            let end_section = result
                .sections
                .iter()
                .find(|s| s.executable && contains(s.address, s.file_size, start))
                .map(|s| s.address.saturating_add(s.file_size));
            if let Some(end) = end_section {
                let next = result
                    .functions
                    .get(index + 1)
                    .map(|f| {
                        f.address
                            & if result.architecture == "arm" {
                                !1
                            } else {
                                u64::MAX
                            }
                    })
                    .unwrap_or(end);
                let bound = next.min(end).saturating_sub(start).min(4096);
                let size = result
                    .decode(f.address, bound as usize, true)
                    .ok()
                    .map(|instructions| {
                        build_cfg(&instructions)
                            .iter()
                            .flat_map(|b| b.instructions.iter())
                            .map(Instruction::end)
                            .max()
                            .unwrap_or(start)
                            .saturating_sub(start)
                    })
                    .unwrap_or(bound);
                result.functions[index].size = size;
                result.functions[index].source.push_str("+inferred-extent");
            }
        }
        self
    }
    fn engine(&self, thumb: bool) -> Result<Capstone> {
        let endian = if self.little_endian {
            capstone::Endian::Little
        } else {
            capstone::Endian::Big
        };
        let mut engine = match self.architecture.as_str() {
            "x86_64" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()?,
            "x86" => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .build()?,
            "aarch64" => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .endian(endian)
                .build()?,
            "arm" => Capstone::new()
                .arm()
                .mode(if thumb {
                    arch::arm::ArchMode::Thumb
                } else {
                    arch::arm::ArchMode::Arm
                })
                .endian(endian)
                .build()?,
            a => bail!("disassembly not implemented for architecture {a}"),
        };
        engine.set_skipdata(true)?;
        Ok(engine)
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({"path":self.path,"sha256":self.sha256,"format":self.format,"architecture":self.architecture,"entry":self.entry,"sections":self.sections.len(),"functions":self.functions.len(),"strings":self.strings.len(),"imports":self.imports.len(),"exports":self.exports.len(),"limitations":self.limitations})
    }
    pub fn snapshot(&self) -> &[u8] {
        &self.bytes
    }

    pub fn file_offset(&self, address: u64) -> Result<u64> {
        let base = if self.architecture == "arm" {
            address & !1
        } else {
            address
        };
        self.sections
            .iter()
            .find(|section| {
                section.executable && contains(section.address, section.file_size, base)
            })
            .and_then(|section| section.file_offset.checked_add(base - section.address))
            .filter(|&offset| offset < self.bytes.len() as u64)
            .with_context(|| format!("no file-backed executable byte at {address:#x}"))
    }

    pub fn bytes_at(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.read_bytes(address, size)
    }
    pub fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        if size > MAX_DISASSEMBLY_BYTES {
            bail!("read limit is 65536 bytes");
        }
        // ARM addresses use bit zero as Thumb state, consistently with disassemble.
        let base = if self.architecture == "arm" {
            address & !1
        } else {
            address
        };
        self.mapped_bytes(base, size).map(|x| x.to_vec())
    }
    fn mapped_bytes(&self, address: u64, size: usize) -> Result<&[u8]> {
        let s = self
            .sections
            .iter()
            .find(|s| contains(s.address, s.file_size, address))
            .ok_or_else(|| anyhow!("unmapped virtual address 0x{address:x}"))?;
        let delta = address - s.address;
        let available = (s.file_size - delta) as usize;
        let start = usize::try_from(
            s.file_offset
                .checked_add(delta)
                .ok_or_else(|| anyhow!("file offset overflow"))?,
        )?;
        let end = start
            .checked_add(size.min(available))
            .ok_or_else(|| anyhow!("range overflow"))?;
        self.bytes
            .get(start..end)
            .ok_or_else(|| anyhow!("section exceeds file bounds"))
    }
    fn decode(&self, address: u64, size: usize, bounded: bool) -> Result<Vec<Instruction>> {
        if bounded && size > MAX_DISASSEMBLY_BYTES {
            bail!("disassembly limit is 65536 bytes");
        }
        let thumb = self.architecture == "arm"
            && (address & 1 == 1
                || self
                    .raw_mapping
                    .as_ref()
                    .is_some_and(|mapping| mapping.mode == "thumb"));
        let base = if thumb { address & !1 } else { address };
        let cs = self.engine(thumb)?;
        let bytes = self.mapped_bytes(base, size)?;
        let mut output = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            // Bounded Capstone instruction batches avoid a single huge native allocation.
            let insns =
                cs.disasm_count(&bytes[cursor..], base.saturating_add(cursor as u64), 4096)?;
            if insns.is_empty() {
                break;
            }
            let consumed = insns.iter().map(|i| i.bytes().len()).sum::<usize>();
            output.extend(insns.iter().map(|i| {
                let mnemonic = i.mnemonic().unwrap_or("").to_owned();
                let operands = i.op_str().unwrap_or("").to_owned();
                let flow = if i.id().0 == 0 {
                    "data"
                } else {
                    classify(&self.architecture, &mnemonic, &operands)
                };
                let target = if matches!(flow, "call" | "jump" | "conditional") {
                    direct_target(&operands)
                } else {
                    None
                };
                Instruction {
                    address: i.address(),
                    bytes: hex::encode(i.bytes()),
                    mnemonic,
                    operands,
                    target,
                    flow: flow.into(),
                }
            }));
            if consumed == 0 {
                break;
            }
            cursor += consumed;
        }
        Ok(output)
    }
    pub fn disassemble(&self, address: u64, size: usize) -> Result<Vec<Instruction>> {
        self.decode(address, size, true)
    }
    pub fn xrefs(&self, address: u64) -> Vec<Xref> {
        self.references
            .iter()
            .filter(|r| r.to == address)
            .cloned()
            .collect()
    }
    pub fn all_xrefs(&self) -> &[Xref] {
        &self.references
    }
    pub fn function(&self, address: u64) -> Result<FunctionDetail> {
        let f = self
            .functions
            .iter()
            .find(|f| f.address == address)
            .cloned()
            .ok_or_else(|| anyhow!("no function seed at 0x{address:x}"))?;
        let mut limitations = self.limitations.clone();
        if f.source != "symbol" || f.size == 4096 {
            limitations.push(
                "Function extent inferred and capped at 4096 bytes; graph may be incomplete."
                    .into(),
            );
        }
        if f.size > MAX_DISASSEMBLY_BYTES as u64 {
            limitations.push("Function output capped at first 65536 bytes.".into());
        }
        let instructions =
            self.disassemble(address, (f.size as usize).min(MAX_DISASSEMBLY_BYTES))?;
        let blocks = build_cfg(&instructions);
        let sites: BTreeSet<_> = instructions.iter().map(|i| i.address).collect();
        let xrefs = self
            .references
            .iter()
            .filter(|r| r.to == address || sites.contains(&r.from))
            .cloned()
            .collect();
        Ok(FunctionDetail {
            function: f,
            instructions,
            xrefs,
            blocks,
            limitations,
        })
    }
}
fn ascii_strings(bytes: &[u8], sections: &[Section]) -> Vec<BinaryString> {
    let mut strings = Vec::new();
    let mut start = 0;
    for end in 0..=bytes.len() {
        if end < bytes.len() && (bytes[end].is_ascii_graphic() || bytes[end] == b' ') {
            continue;
        }
        if end - start >= 4 {
            let offset = start as u64;
            let address = sections
                .iter()
                .find(|s| contains(s.file_offset, s.file_size, offset))
                .and_then(|s| s.address.checked_add(offset - s.file_offset));
            strings.push(BinaryString {
                file_offset: offset,
                address,
                value: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
            });
            if strings.len() >= 200_000 {
                break;
            }
        }
        start = end + 1;
    }
    strings
}

fn contains(base: u64, size: u64, value: u64) -> bool {
    value >= base && value - base < size
}
fn direct_target(operands: &str) -> Option<u64> {
    let last = operands.rsplit(',').next()?.trim().trim_start_matches('#');
    // Registers, memory operands and expressions deliberately stay unresolved.
    if let Some(hex) = last.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if last.chars().all(|c| c.is_ascii_digit()) && !last.is_empty() {
        last.parse().ok()
    } else {
        None
    }
}
fn classify<'a>(arch: &str, m: &str, operands: &str) -> &'a str {
    if arch.starts_with("x86") {
        if m.starts_with("ret") || m == "iret" || m == "iretq" {
            "return"
        } else if m == "call" || m == "lcall" {
            "call"
        } else if m == "jmp" || m == "ljmp" {
            "jump"
        } else if m.starts_with('j') || m.starts_with("loop") {
            "conditional"
        } else if m == "ud2" || m == "hlt" {
            "stop"
        } else {
            "normal"
        }
    } else {
        if m == "ret"
            || (m == "bx" && operands.trim() == "lr")
            || (m == "pop" && operands.contains("pc"))
        {
            "return"
        } else if m == "bl" || m == "blx" || m == "blr" {
            "call"
        } else if m == "b" || m == "br" || m == "bx" {
            "jump"
        } else if m.starts_with("b.")
            || matches!(
                m,
                "beq"
                    | "bne"
                    | "bgt"
                    | "bge"
                    | "blt"
                    | "ble"
                    | "bhi"
                    | "bls"
                    | "bhs"
                    | "blo"
                    | "bmi"
                    | "bpl"
                    | "bvs"
                    | "bvc"
                    | "cbz"
                    | "cbnz"
                    | "tbz"
                    | "tbnz"
            )
        {
            "conditional"
        } else if m == "brk" || m == "udf" {
            "stop"
        } else {
            "normal"
        }
    }
}
fn build_cfg(insns: &[Instruction]) -> Vec<BasicBlock> {
    let Some(first) = insns.first() else {
        return vec![];
    };
    let map: BTreeMap<_, _> = insns.iter().map(|i| (i.address, i)).collect();
    let mut leaders = BTreeSet::from([first.address]);
    for i in insns {
        if matches!(i.flow.as_str(), "jump" | "conditional") {
            if let Some(t) = i.target {
                if map.contains_key(&t) {
                    leaders.insert(t);
                }
            }
        }
        if matches!(
            i.flow.as_str(),
            "jump" | "conditional" | "return" | "stop" | "data"
        ) && map.contains_key(&i.end())
        {
            leaders.insert(i.end());
        }
    }
    let mut blocks = BTreeMap::new();
    for start in &leaders {
        let mut body = Vec::new();
        let mut current = *start;
        while let Some(i) = map.get(&current) {
            body.push((*i).clone());
            current = i.end();
            if matches!(
                i.flow.as_str(),
                "jump" | "conditional" | "return" | "stop" | "data"
            ) || leaders.contains(&current)
            {
                break;
            }
        }
        let mut successors = Vec::new();
        if let Some(i) = body.last() {
            if matches!(i.flow.as_str(), "jump" | "conditional") {
                if let Some(t) = i.target {
                    successors.push(t);
                }
            }
            if !matches!(i.flow.as_str(), "jump" | "return" | "stop" | "data")
                && map.contains_key(&i.end())
            {
                successors.push(i.end());
            }
        }
        blocks.insert(
            *start,
            BasicBlock {
                address: *start,
                instructions: body,
                successors,
            },
        );
    }
    // Retain reachable blocks only. External edges remain declared without inventing a block.
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([first.address]);
    while let Some(a) = queue.pop_front() {
        if !seen.insert(a) {
            continue;
        }
        if let Some(b) = blocks.get(&a) {
            for s in &b.successors {
                if blocks.contains_key(s) {
                    queue.push_back(*s);
                }
            }
        }
    }
    blocks
        .into_values()
        .filter(|b| seen.contains(&b.address))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WriteObject, Symbol as WriteSymbol, SymbolSection};
    use object::{BinaryFormat, Endianness, SymbolFlags, SymbolScope};
    fn fixture(format: BinaryFormat, arch: object::Architecture, code: &[u8]) -> Vec<u8> {
        let mut o = WriteObject::new(format, arch, Endianness::Little);
        let section = o.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        o.append_section_data(section, code, 4);
        o.add_symbol(WriteSymbol {
            name: b"test_function".to_vec(),
            value: 0,
            size: code.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
        o.write().unwrap()
    }
    #[test]
    fn x64_cfg_and_direct_calls() {
        // cmp edi,0; je +6; call +1; ret; ret
        let bytes = fixture(
            BinaryFormat::Elf,
            object::Architecture::X86_64,
            &[0x83, 0xff, 0, 0x74, 6, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3],
        );
        let a = Analysis::from_bytes("fixture".into(), bytes).unwrap();
        assert_eq!(a.architecture, "x86_64");
        assert_eq!(a.xrefs(11).len(), 2);
        let d = a.function(0).unwrap();
        assert_eq!(d.blocks.len(), 3);
        assert_eq!(d.blocks[0].successors, vec![11, 5]);
        assert_eq!(d.instructions[2].flow, "call");
    }
    #[test]
    fn arm64_return() {
        let a = Analysis::from_bytes(
            "arm".into(),
            fixture(
                BinaryFormat::MachO,
                object::Architecture::Aarch64,
                &[0xc0, 3, 0x5f, 0xd6],
            ),
        )
        .unwrap();
        assert_eq!(a.disassemble(0, 4).unwrap()[0].flow, "return");
    }
    #[test]
    fn pe_coff_x86() {
        let a = Analysis::from_bytes(
            "coff".into(),
            fixture(
                BinaryFormat::Coff,
                object::Architecture::I386,
                &[0x31, 0xc0, 0xc3],
            ),
        )
        .unwrap();
        assert_eq!(a.disassemble(0, 3).unwrap().len(), 2);
    }
    #[test]
    fn rejects_malformed_and_unmapped() {
        assert!(Analysis::from_bytes("bad".into(), vec![0; 32]).is_err());
        let a = Analysis::from_bytes(
            "x".into(),
            fixture(BinaryFormat::Elf, object::Architecture::X86_64, &[0xc3]),
        )
        .unwrap();
        assert!(a.disassemble(0xffff_ffff, 1).is_err());
        assert!(a.disassemble(0, 65537).is_err());
    }
    #[test]
    fn arm_and_thumb_modes() {
        let a = Analysis::from_bytes(
            "arm".into(),
            fixture(
                BinaryFormat::Elf,
                object::Architecture::Arm,
                &[0x1e, 0xff, 0x2f, 0xe1],
            ),
        )
        .unwrap();
        assert_eq!(a.disassemble(0, 4).unwrap()[0].flow, "return");
        let t = Analysis::from_bytes(
            "thumb".into(),
            fixture(BinaryFormat::Elf, object::Architecture::Arm, &[0x70, 0x47]),
        )
        .unwrap();
        let decoded = t.disassemble(1, 2).unwrap();
        assert_eq!(decoded[0].address, 0);
        assert_eq!(decoded[0].flow, "return");
        assert_eq!(t.read_bytes(1, 2).unwrap(), vec![0x70, 0x47]);
    }
    #[test]
    fn inferred_extent_stops_at_return_and_filters_unmapped_text() {
        let mut object = WriteObject::new(
            BinaryFormat::Elf,
            object::Architecture::X86_64,
            Endianness::Little,
        );
        let text = object.add_section(vec![], b".text".to_vec(), SectionKind::Text);
        object.append_section_data(text, &[0xc3, 0x90, 0x90], 1);
        object.add_symbol(WriteSymbol {
            name: b"function".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        object.add_symbol(WriteSymbol {
            name: b"unmapped_text_label".to_vec(),
            value: 0x1000,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Absolute,
            flags: SymbolFlags::None,
        });
        let a = Analysis::from_bytes("inferred".into(), object.write().unwrap()).unwrap();
        assert_eq!(a.functions.len(), 1);
        assert_eq!(a.functions[0].size, 1);
        assert!(a.functions[0].source.contains("inferred-extent"));
    }
    #[test]
    fn invalid_bytes_end_cfg_flow() {
        let a = Analysis::from_bytes(
            "invalid".into(),
            fixture(
                BinaryFormat::MachO,
                object::Architecture::Aarch64,
                &[0xff, 0xff, 0xff, 0xff, 0xc0, 3, 0x5f, 0xd6],
            ),
        )
        .unwrap();
        let decoded = a.disassemble(0, 8).unwrap();
        assert_eq!(decoded[0].flow, "data");
        let cfg = build_cfg(&decoded);
        assert_eq!(cfg.len(), 1);
        assert!(cfg[0].successors.is_empty());
    }
    #[test]
    fn macho_lc_main_file_offset_converts_to_virtual_address() {
        // Minimal thin MH_EXECUTE: 64-bit header, one text segment+section, LC_MAIN.
        let mut bytes = vec![0u8; 209];
        let put32 =
            |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |b: &mut Vec<u8>, o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        put32(&mut bytes, 0, 0xfeedfacf);
        put32(&mut bytes, 4, 0x01000007);
        put32(&mut bytes, 8, 3);
        put32(&mut bytes, 12, 2);
        put32(&mut bytes, 16, 2);
        put32(&mut bytes, 20, 176);
        put32(&mut bytes, 32, 0x19);
        put32(&mut bytes, 36, 152);
        bytes[40..46].copy_from_slice(b"__TEXT");
        put64(&mut bytes, 56, 0x100000000);
        put64(&mut bytes, 64, 4096);
        put64(&mut bytes, 72, 0);
        put64(&mut bytes, 80, 209);
        put32(&mut bytes, 88, 5);
        put32(&mut bytes, 92, 5);
        put32(&mut bytes, 96, 1);
        bytes[104..110].copy_from_slice(b"__text");
        bytes[120..126].copy_from_slice(b"__TEXT");
        put64(&mut bytes, 136, 0x1000000d0);
        put64(&mut bytes, 144, 1);
        put32(&mut bytes, 152, 208);
        put32(&mut bytes, 168, 0x80000400);
        put32(&mut bytes, 184, 0x80000028);
        put32(&mut bytes, 188, 24);
        put64(&mut bytes, 192, 208);
        bytes[208] = 0xc3;
        let a = Analysis::from_bytes("macho".into(), bytes).unwrap();
        assert_eq!(a.entry, 0x1000000d0);
        assert_eq!(a.functions[0].address, a.entry);
    }
    #[test]
    fn entropy_extremes() {
        assert_eq!(entropy(&[0; 8]), 0.);
        assert!((entropy(&(0..=255).collect::<Vec<u8>>()) - 8.).abs() < 1e-10);
    }
    #[test]
    fn no_indirect_fabrication() {
        assert_eq!(direct_target("rax"), None);
        assert_eq!(direct_target("qword ptr [rip + 0x40]"), None);
        assert_eq!(direct_target("x0, #0x1000"), Some(4096));
    }
}
