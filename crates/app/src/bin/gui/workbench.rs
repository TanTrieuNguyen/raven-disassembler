use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, Vec2};
use raven_core::{Analysis, FunctionDetail};
use std::collections::{BTreeMap, VecDeque};

pub fn icon() -> anyhow::Result<egui::IconData> {
    let logo = image::load_from_memory_with_format(
        include_bytes!("../../../assets/raven-logo.jpg"),
        image::ImageFormat::Jpeg,
    )?;
    // Use the supplied bird mark for compact UI surfaces and retain the original wordmark asset.
    let mark = logo.crop_imm(325, 331, 840, 840);
    let rgba = mark
        .resize_exact(128, 128, image::imageops::FilterType::Lanczos3)
        .to_rgba8();
    Ok(egui::IconData {
        rgba: rgba.into_raw(),
        width: 128,
        height: 128,
    })
}

pub fn hex_view(ui: &mut egui::Ui, analysis: &Analysis, address: u64) -> Option<u64> {
    ui.heading("Hex bytes");
    let mapped = if analysis.architecture == "arm" {
        address & !1
    } else {
        address
    };
    let section_start = analysis
        .sections
        .iter()
        .find(|section| {
            mapped
                .checked_sub(section.address)
                .is_some_and(|delta| delta < section.file_size)
        })
        .map_or(mapped, |section| section.address);
    let page = (mapped - section_start) / 256;
    let base = section_start + page * 256;
    let bytes = match analysis.read_bytes(base, 256) {
        Ok(bytes) => bytes,
        Err(error) => {
            ui.label(error.to_string());
            return None;
        }
    };
    let mut jump = None;
    let selected_address = address;
    ui.label(format!(
        "Cursor {address:#x} · {} file-backed bytes",
        bytes.len()
    ));
    ui.horizontal(|ui| {
        if ui
            .add_enabled(page != 0, egui::Button::new("Previous"))
            .clicked()
        {
            jump = Some(base - 256);
        }
        if let Some(next) = base
            .checked_add(bytes.len() as u64)
            .filter(|next| analysis.read_bytes(*next, 1).is_ok())
        {
            if ui.button("Next").clicked() {
                jump = Some(next);
            }
        }
    });
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("raven-hex-grid")
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Address");
                for index in 0..16 {
                    ui.monospace(format!("{index:02X}"));
                }
                ui.strong("ASCII");
                ui.end_row();
                for (row, chunk) in bytes.chunks(16).enumerate() {
                    let row_address = base + (row * 16) as u64;
                    ui.monospace(format!("{row_address:016x}"));
                    for (index, byte) in chunk.iter().enumerate() {
                        let address = row_address + index as u64;
                        if ui
                            .selectable_label(
                                address == selected_address,
                                RichText::new(format!("{byte:02x}")).monospace(),
                            )
                            .clicked()
                        {
                            jump = Some(address);
                        }
                    }
                    for _ in chunk.len()..16 {
                        ui.label("");
                    }
                    let ascii: String = chunk
                        .iter()
                        .map(|b| {
                            if b.is_ascii_graphic() || *b == b' ' {
                                char::from(*b)
                            } else {
                                '·'
                            }
                        })
                        .collect();
                    ui.monospace(ascii);
                    ui.end_row();
                }
            });
    });
    jump
}

pub fn graph_view(
    ui: &mut egui::Ui,
    detail: &FunctionDetail,
    selected: Option<u64>,
    zoom: &mut f32,
) -> Option<u64> {
    const LIMIT: usize = 160;
    let blocks: BTreeMap<_, _> = detail
        .blocks
        .iter()
        .take(LIMIT)
        .map(|block| (block.address, block))
        .collect();
    ui.horizontal(|ui| {
        ui.heading("Control flow");
        ui.add(egui::Slider::new(zoom, 0.6..=1.5).text("Zoom"));
    });
    let Some(entry) = detail.blocks.first().map(|block| block.address) else {
        ui.label("No reachable basic blocks recovered.");
        return None;
    };
    let mut depth = BTreeMap::from([(entry, 0usize)]);
    let mut queue = VecDeque::from([entry]);
    while let Some(address) = queue.pop_front() {
        for &target in &blocks[&address].successors {
            if blocks.contains_key(&target) && !depth.contains_key(&target) {
                depth.insert(target, depth[&address] + 1);
                queue.push_back(target);
            }
        }
    }
    let shown = depth.len();
    ui.label(format!(
        "{shown} of {} blocks · Select a block to inspect its address",
        detail.blocks.len()
    ));
    let mut levels: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
    for (address, level) in depth {
        levels.entry(level).or_default().push(address);
    }
    let scale = *zoom;
    let node = Vec2::new(254.0, 96.0) * scale;
    let spacing = Vec2::new(290.0, 145.0) * scale;
    let columns = levels.values().map(Vec::len).max().unwrap_or(1);
    let mut jump = None;
    egui::ScrollArea::both()
        .id_salt("raven-flow-canvas")
        .show(ui, |ui| {
            let size = Vec2::new(
                spacing.x * columns as f32 + 36.0,
                spacing.y * levels.len() as f32 + 24.0,
            );
            let (canvas, painter) = ui.allocate_painter(size, Sense::hover());
            let origin = canvas.rect.min + Vec2::new(18.0, 12.0);
            let mut positions = BTreeMap::new();
            for (row, addresses) in levels.values().enumerate() {
                let inset = (columns - addresses.len()) as f32 * spacing.x * 0.5;
                for (column, &address) in addresses.iter().enumerate() {
                    let top_left = origin
                        + Vec2::new(inset + column as f32 * spacing.x, row as f32 * spacing.y);
                    positions.insert(address, Rect::from_min_size(top_left, node));
                }
            }
            let visuals = ui.visuals();
            let edge = Stroke::new(1.4_f32, visuals.weak_text_color());
            for (&address, &rect) in &positions {
                for target in &blocks[&address].successors {
                    let Some(&target_rect) = positions.get(target) else {
                        continue;
                    };
                    let (start, finish, elbow) = if target_rect.top() > rect.bottom() {
                        let start = rect.center_bottom();
                        let finish = target_rect.center_top();
                        (
                            start,
                            finish,
                            Pos2::new(finish.x, (start.y + finish.y) / 2.0),
                        )
                    } else {
                        let start = rect.right_center();
                        let finish = target_rect.right_center();
                        (
                            start,
                            finish,
                            Pos2::new(start.x.max(finish.x) + 10.0 * scale, finish.y),
                        )
                    };
                    let corner = if target_rect.top() > rect.bottom() {
                        Pos2::new(start.x, elbow.y)
                    } else {
                        Pos2::new(elbow.x, start.y)
                    };
                    painter.add(egui::Shape::line(vec![start, corner, elbow], edge));
                    let vector = finish - elbow;
                    if vector.length_sq() > 0.0 {
                        let tip = vector.normalized() * (7.0 * scale).min(vector.length());
                        painter.line_segment([elbow, finish - tip], edge);
                        painter.arrow(finish - tip, tip, edge);
                    }
                }
            }
            for (&address, &rect) in &positions {
                let block = blocks[&address];
                let active = selected.is_some_and(|cursor| {
                    block
                        .instructions
                        .iter()
                        .any(|instruction| instruction.address == cursor)
                });
                let fill = if active {
                    visuals.selection.bg_fill
                } else {
                    visuals.faint_bg_color
                };
                let border = if active {
                    visuals.selection.stroke
                } else {
                    visuals.widgets.noninteractive.bg_stroke
                };
                let text = if active {
                    visuals.selection.stroke.color
                } else {
                    visuals.text_color()
                };
                painter.rect(rect, 7, fill, border, egui::StrokeKind::Inside);
                let body = painter.with_clip_rect(rect.intersect(painter.clip_rect()));
                body.text(
                    rect.min + Vec2::new(10.0, 8.0) * scale,
                    Align2::LEFT_TOP,
                    format!("{address:#018x}"),
                    FontId::monospace(13.0 * scale),
                    text,
                );
                for (index, instruction) in block.instructions.iter().take(3).enumerate() {
                    body.text(
                        rect.min + Vec2::new(10.0, 29.0 + 15.0 * index as f32) * scale,
                        Align2::LEFT_TOP,
                        format!("{} {}", instruction.mnemonic, instruction.operands),
                        FontId::monospace(11.0 * scale),
                        text,
                    );
                }
                if block.instructions.len() > 3 {
                    body.text(
                        rect.left_bottom() + Vec2::new(10.0, -5.0) * scale,
                        Align2::LEFT_BOTTOM,
                        format!("+{} instructions", block.instructions.len() - 3),
                        FontId::monospace(10.0 * scale),
                        text,
                    );
                }
                let response = ui.interact(rect, ui.id().with(address), Sense::click());
                if response
                    .on_hover_text(format!(
                        "{} instructions · {} successors",
                        block.instructions.len(),
                        block.successors.len()
                    ))
                    .clicked()
                {
                    jump = Some(address);
                }
            }
        });
    jump
}

pub fn address_tint(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(142, 196, 216)
    } else {
        Color32::from_rgb(28, 96, 123)
    }
}
