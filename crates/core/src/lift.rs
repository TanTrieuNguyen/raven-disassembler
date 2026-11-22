//! A bounded x86-64 lifter for straight-line integer functions.
use super::Analysis;
use anyhow::{bail, ensure, Context, Result};
use capstone::{arch::x86::X86OperandType, prelude::*};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
struct Register {
    name: &'static str,
    width: u8,
}

fn register(name: &str) -> Option<Register> {
    let (name, width) = match name {
        "rax" => ("rax", 64),
        "eax" => ("rax", 32),
        "rbx" => ("rbx", 64),
        "ebx" => ("rbx", 32),
        "rcx" => ("rcx", 64),
        "ecx" => ("rcx", 32),
        "rdx" => ("rdx", 64),
        "edx" => ("rdx", 32),
        "rsi" => ("rsi", 64),
        "esi" => ("rsi", 32),
        "rdi" => ("rdi", 64),
        "edi" => ("rdi", 32),
        "r8" => ("r8", 64),
        "r8d" => ("r8", 32),
        "r9" => ("r9", 64),
        "r9d" => ("r9", 32),
        "r10" => ("r10", 64),
        "r10d" => ("r10", 32),
        "r11" => ("r11", 64),
        "r11d" => ("r11", 32),
        "r12" => ("r12", 64),
        "r12d" => ("r12", 32),
        "r13" => ("r13", 64),
        "r13d" => ("r13", 32),
        "r14" => ("r14", 64),
        "r14d" => ("r14", 32),
        "r15" => ("r15", 64),
        "r15d" => ("r15", 32),
        _ => return None,
    };
    Some(Register { name, width })
}

#[derive(Clone, Copy)]
enum Source {
    Register(Register),
    Immediate(u64),
}

#[derive(Clone, Copy)]
enum Op {
    Mov,
    Add,
    Sub,
    And,
    Or,
    Xor,
    Mul,
}

impl Op {
    fn symbol(self) -> Option<&'static str> {
        match self {
            Self::Mov => None,
            Self::Add => Some("+"),
            Self::Sub => Some("-"),
            Self::And => Some("&"),
            Self::Or => Some("|"),
            Self::Xor => Some("^"),
            Self::Mul => Some("*"),
        }
    }

    fn evaluate(self, left: u64, right: u64) -> u64 {
        match self {
            Self::Mov => right,
            Self::Add => left.wrapping_add(right),
            Self::Sub => left.wrapping_sub(right),
            Self::And => left & right,
            Self::Or => left | right,
            Self::Xor => left ^ right,
            Self::Mul => left.wrapping_mul(right),
        }
    }
}

struct Operation {
    destination: Register,
    source: Source,
    kind: Op,
}

struct Lifted {
    abi: &'static str,
    parameters: Vec<(&'static str, u8)>,
    operations: Vec<Operation>,
    return_width: u8,
}

fn truncate(value: u64, width: u8) -> u64 {
    if width == 32 {
        u64::from(value as u32)
    } else {
        value
    }
}

impl Lifted {
    fn read_register(
        register: Register,
        defined: &BTreeMap<&'static str, u8>,
        inputs: &mut BTreeMap<&'static str, u8>,
        abi_regs: &[&str],
    ) -> Result<()> {
        if !defined.contains_key(register.name) {
            ensure!(
                abi_regs.contains(&register.name),
                "read of unknown register {}",
                register.name
            );
            let width = inputs.entry(register.name).or_insert(register.width);
            *width = (*width).max(register.width);
        }
        Ok(())
    }

    fn decode(analysis: &Analysis, address: u64, abi: Option<&str>) -> Result<Self> {
        ensure!(
            analysis.architecture == "x86_64",
            "native lifting currently supports x86-64"
        );
        let (abi, abi_regs): (_, &[&str]) = match abi.unwrap_or(if analysis.format == "Pe" {
            "win64"
        } else {
            "sysv"
        }) {
            "sysv" => ("sysv", &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
            "win64" => ("win64", &["rcx", "rdx", "r8", "r9"]),
            _ => bail!("ABI must be sysv or win64"),
        };
        let function = analysis
            .functions
            .iter()
            .find(|function| function.address == address)
            .context("native lifting requires a known function entry")?;
        let code = analysis.mapped_bytes(address, function.size.min(512) as usize)?;
        let capstone = analysis.engine(false)?;
        let instructions = capstone.disasm_all(code, address)?;
        let mut operations = Vec::new();
        let mut defined = BTreeMap::new();
        let mut inputs = BTreeMap::new();
        let parse_register = |id| {
            capstone
                .reg_name(id)
                .and_then(|name| register(&name))
                .context("unsupported register width or register class")
        };
        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            if mnemonic == "ret" && insn.bytes() == [0xc3] {
                let return_width = *defined
                    .get("rax")
                    .context("return register was not assigned")?;
                let parameters = abi_regs
                    .iter()
                    .rposition(|name| inputs.contains_key(name))
                    .map(|last| {
                        abi_regs[..=last]
                            .iter()
                            .map(|&name| (name, inputs.get(name).copied().unwrap_or(64)))
                            .collect()
                    })
                    .unwrap_or_default();
                return Ok(Self {
                    abi,
                    parameters,
                    operations,
                    return_width,
                });
            }
            if matches!(mnemonic, "endbr64" | "nop") {
                continue;
            }
            let kind = match mnemonic {
                "mov" | "movabs" => Op::Mov,
                "add" => Op::Add,
                "sub" => Op::Sub,
                "and" => Op::And,
                "or" => Op::Or,
                "xor" => Op::Xor,
                "imul" => Op::Mul,
                _ => bail!(
                    "unsupported instruction {mnemonic} at {:#x}",
                    insn.address()
                ),
            };
            let detail = capstone.insn_detail(insn)?;
            let arch = detail.arch_detail();
            let ops: Vec<_> = arch
                .x86()
                .context("missing x86 operand detail")?
                .operands()
                .collect();
            let [dest, value] = ops.as_slice() else {
                bail!("unsupported operand count at {:#x}", insn.address());
            };
            let X86OperandType::Reg(dest_id) = dest.op_type else {
                bail!("memory destinations are outside the native model");
            };
            let destination = parse_register(dest_id)?;
            let mut source = match value.op_type {
                X86OperandType::Reg(id) => Source::Register(parse_register(id)?),
                X86OperandType::Imm(value) => Source::Immediate(value as u64),
                _ => bail!("memory and unknown operands are outside the native model"),
            };
            let mut kind = kind;
            // XOR of a register with itself always clears it without an input.
            if matches!(kind, Op::Xor)
                && matches!(source, Source::Register(reg) if reg.name == destination.name && reg.width == destination.width)
            {
                kind = Op::Mov;
                source = Source::Immediate(0);
            }
            if !matches!(kind, Op::Mov) {
                Self::read_register(destination, &defined, &mut inputs, abi_regs)?;
            }
            if let Source::Register(reg) = source {
                Self::read_register(reg, &defined, &mut inputs, abi_regs)?;
            }
            defined.insert(destination.name, destination.width);
            operations.push(Operation {
                destination,
                source,
                kind,
            });
        }
        bail!("no supported return within the function's first 512 bytes");
    }

    fn prototype(&self) -> String {
        let parameters = self
            .parameters
            .iter()
            .enumerate()
            .map(|(index, (_, bits))| format!("uint{bits}_t arg{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let parameters = if parameters.is_empty() {
            "void"
        } else {
            &parameters
        };
        format!("uint{}_t raven_function({parameters})", self.return_width)
    }

    fn pseudocode(&self) -> String {
        let mut output = format!("#include <stdint.h>\n\n{} {{\n", self.prototype());
        let mut locals = BTreeSet::new();
        for (index, (reg, _)) in self.parameters.iter().enumerate() {
            output += &format!("  uint64_t {reg} = arg{index};\n");
            locals.insert(*reg);
        }
        for op in &self.operations {
            let destination = op.destination;
            let source = match op.source {
                Source::Immediate(value) => format!("UINT64_C({value:#x})"),
                Source::Register(reg) if reg.width == 32 => {
                    format!("(uint64_t)(uint32_t){}", reg.name)
                }
                Source::Register(reg) => reg.name.to_owned(),
            };
            let expression = if let Some(symbol) = op.kind.symbol() {
                format!("{} {symbol} {source}", destination.name)
            } else {
                source
            };
            let declaration = if locals.insert(destination.name) {
                "uint64_t "
            } else {
                ""
            };
            output += &format!(
                "  {declaration}{} = (uint{}_t)({expression});\n",
                destination.name, destination.width
            );
        }
        output += &format!("  return (uint{}_t)rax;\n}}\n", self.return_width);
        output
    }

    fn emulate(&self, arguments: &[u64]) -> Result<u64> {
        ensure!(
            arguments.len() == self.parameters.len(),
            "expected {} integer arguments",
            self.parameters.len()
        );
        let mut registers: BTreeMap<_, _> = self
            .parameters
            .iter()
            .zip(arguments)
            .map(|(&(reg, width), &argument)| (reg, truncate(argument, width)))
            .collect();
        for op in &self.operations {
            let right = match op.source {
                Source::Register(reg) => truncate(registers[reg.name], reg.width),
                Source::Immediate(value) => value,
            };
            let left = registers
                .get(op.destination.name)
                .copied()
                .unwrap_or_default();
            registers.insert(
                op.destination.name,
                truncate(op.kind.evaluate(left, right), op.destination.width),
            );
        }
        Ok(truncate(registers["rax"], self.return_width))
    }
}

impl Analysis {
    pub fn lift_integer_function(
        &self,
        address: u64,
        abi: Option<&str>,
        arguments: Option<&[u64]>,
    ) -> Result<Value> {
        let lifted = Lifted::decode(self, address, abi)?;
        let result = arguments.map(|args| lifted.emulate(args)).transpose()?;
        Ok(json!({
            "provider": "RAVEN native lifter",
            "abi": lifted.abi,
            "address": format!("{address:#x}"),
            "prototype": lifted.prototype(),
            "pseudocode": lifted.pseudocode(),
            "argument_widths": lifted.parameters.iter().map(|(_, bits)| *bits).collect::<Vec<_>>(),
            "return_width": lifted.return_width,
            "return_value": result.map(|value| format!("{value:#x}")),
            "limitations": ["Widths are inferred from register usage. Signedness, pointers, structures, branches, calls and memory are outside this model."],
        }))
    }
}
