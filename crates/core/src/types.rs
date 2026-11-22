use super::Analysis;
use anyhow::{Context, Result};
use gimli::{AttributeValue, DwarfSections, EndianSlice, Reader, RunTimeEndian};
use object::{Object, ObjectSection};
use serde::Serialize;
use std::borrow::Cow;

#[derive(Serialize)]
struct DebugType {
    id: usize,
    kind: &'static str,
    name: Option<String>,
    byte_size: Option<u64>,
    encoding: Option<&'static str>,
    type_ref: Option<usize>,
    members: Vec<Member>,
}

#[derive(Serialize)]
struct Member {
    name: Option<String>,
    kind: &'static str,
    type_ref: Option<usize>,
    byte_offset: Option<u64>,
    bit_offset: Option<u64>,
    bit_size: Option<u64>,
    count: Option<u64>,
    value: Option<String>,
}

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

fn name(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<String> {
    let attr = entry.attr_value(gimli::DW_AT_name).ok()??;
    let string = dwarf.attr_string(unit, attr).ok()?;
    let bytes = string.to_slice().ok()?;
    Some(String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).into_owned())
}

fn reference(
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
) -> Option<usize> {
    match entry.attr_value(gimli::DW_AT_type).ok()?? {
        AttributeValue::UnitRef(offset) => Some(offset.to_debug_info_offset(&unit.header)?.0),
        AttributeValue::DebugInfoRef(offset) => Some(offset.0),
        _ => None,
    }
}

fn type_tag(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_base_type
            | gimli::DW_TAG_typedef
            | gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_array_type
            | gimli::DW_TAG_subroutine_type
    )
}

impl Analysis {
    /// Read declared DWARF types from the loaded snapshot. Report IDs in .debug_info.
    pub fn debug_types(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        anyhow::ensure!(
            self.raw_mapping.is_none(),
            "raw images have no DWARF section table"
        );
        anyhow::ensure!((1..=100).contains(&limit), "limit must be 1..=100");
        let file = object::File::parse(self.snapshot())?;
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let mut remaining_bytes = 64 * 1024 * 1024u64;
        let sections = DwarfSections::load(|id: gimli::SectionId| -> Result<Cow<'_, [u8]>> {
            let standard = id.name();
            let suffix = standard.trim_start_matches(".debug_");
            let macho = format!("__debug_{suffix}");
            let gnu = format!(".zdebug_{suffix}");
            let Some(section) = file
                .section_by_name(standard)
                .or_else(|| file.section_by_name(&macho))
                .or_else(|| file.section_by_name(&gnu))
            else {
                return Ok(Cow::Borrowed(&[]));
            };
            let compressed = section.compressed_data()?;
            remaining_bytes = remaining_bytes
                .checked_sub(compressed.uncompressed_size)
                .context("DWARF exceeds the aggregate 64 MiB decode budget")?;
            Ok(compressed.decompress()?)
        })?;
        let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
        let mut result: Vec<DebugType> = Vec::new();
        let mut units = dwarf.units();
        let mut entries_seen = 0;
        let mut matches = 0usize;
        let mut has_more = false;
        let mut truncated_children = false;
        'units: while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            let mut depth = 0isize;
            let mut parents: Vec<(isize, Option<usize>)> = Vec::new();
            while let Some((delta, entry)) = entries.next_dfs()? {
                entries_seen += 1;
                depth += delta;
                if entries_seen > 500_000 || depth > 512 {
                    has_more = true;
                    break 'units;
                }
                parents.retain(|(level, _)| *level < depth);
                let tag = entry.tag();
                let read_unsigned = |attribute| {
                    entry
                        .attr_value(attribute)
                        .ok()
                        .flatten()
                        .and_then(|value| {
                            value.udata_value().or_else(|| {
                                value
                                    .sdata_value()
                                    .and_then(|value| u64::try_from(value).ok())
                            })
                        })
                };
                if type_tag(tag) {
                    let name = name(&dwarf, &unit, entry);
                    let id = entry.offset().to_debug_info_offset(&unit.header);
                    let mut index = None;
                    if let Some(id) = id.filter(|_| {
                        query.is_empty() || name.as_deref().is_some_and(|name| name.contains(query))
                    }) {
                        if matches >= offset && result.len() < limit {
                            index = Some(result.len());
                            result.push(DebugType {
                                id: id.0,
                                kind: tag.static_string().unwrap_or("unknown"),
                                name,
                                byte_size: read_unsigned(gimli::DW_AT_byte_size),
                                encoding: match entry.attr_value(gimli::DW_AT_encoding)? {
                                    Some(AttributeValue::Encoding(encoding)) => {
                                        encoding.static_string()
                                    }
                                    _ => None,
                                },
                                type_ref: reference(&unit, entry),
                                members: Vec::new(),
                            });
                        }
                        matches += 1;
                    }
                    parents.push((depth, index));
                } else if matches!(
                    tag,
                    gimli::DW_TAG_member
                        | gimli::DW_TAG_enumerator
                        | gimli::DW_TAG_subrange_type
                        | gimli::DW_TAG_formal_parameter
                        | gimli::DW_TAG_inheritance
                ) {
                    let Some((_, Some(index))) =
                        parents.last().filter(|(level, _)| *level + 1 == depth)
                    else {
                        continue;
                    };
                    let members = &mut result[*index].members;
                    if members.len() == 256 {
                        truncated_children = true;
                        continue;
                    }
                    let value = match entry.attr_value(gimli::DW_AT_const_value)? {
                        Some(AttributeValue::Sdata(value)) => Some(value.to_string()),
                        Some(value) => value.udata_value().map(|value| value.to_string()),
                        None => None,
                    };
                    members.push(Member {
                        name: name(&dwarf, &unit, entry),
                        kind: tag.static_string().unwrap_or("unknown"),
                        type_ref: reference(&unit, entry),
                        byte_offset: read_unsigned(gimli::DW_AT_data_member_location),
                        bit_offset: read_unsigned(gimli::DW_AT_data_bit_offset),
                        bit_size: read_unsigned(gimli::DW_AT_bit_size),
                        count: read_unsigned(gimli::DW_AT_count),
                        value,
                    });
                }
            }
        }
        Ok(serde_json::json!({
            "source":"embedded DWARF .debug_info",
            "address_space":"type IDs and type_ref are section offsets, not virtual addresses",
            "items":result,
            "next_offset": (matches > offset.saturating_add(result.len())).then(|| offset.saturating_add(result.len())),
            "visited_entries":entries_seen.min(500_000),
            "scan_truncated":has_more,
            "members_truncated":truncated_children,
            "limitations":["Requires embedded DWARF. No PDB, external dSYM discovery or split DWARF.",
                "Dynamic member locations and unresolved external type references remain unknown. Types are compiler declarations, not inferred from stripped code."]
        }))
    }
}
