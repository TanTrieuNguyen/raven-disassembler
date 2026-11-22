use eframe::egui::{self, RichText};
#[path = "gui/workbench.rs"]
mod workbench;

const LISTING: usize = 0;
const GRAPH: usize = 1;
const HEX: usize = 10;
use raven::{parse_address, Workspace};
use raven_core::{Analysis, FunctionDetail};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::mpsc};
struct App {
    ws: Workspace,
    path: String,
    query: String,
    string_query: String,
    address: String,
    cursor: Option<u64>,
    back: Vec<u64>,
    forward: Vec<u64>,
    graph_zoom: f32,
    inspector_code: bool,
    logo: Option<egui::TextureHandle>,
    listing_scroll: bool,
    tab: usize,
    detail: Option<FunctionDetail>,
    output: String,
    pseudocode: String,
    decompiling: Option<mpsc::Receiver<anyhow::Result<Value>>>,
    status: String,
    loading: Option<mpsc::Receiver<anyhow::Result<Analysis>>>,
    name: String,
    comment: String,
    revision: u64,
    dark: bool,
    tool: String,
    args: String,
}
impl App {
    fn new(db: PathBuf, path: String) -> anyhow::Result<Self> {
        let mut result = Self {
            ws: Workspace::new(&db)?,
            path,
            query: String::new(),
            string_query: String::new(),
            address: String::new(),
            cursor: None,
            back: Vec::new(),
            forward: Vec::new(),
            graph_zoom: 1.0,
            inspector_code: false,
            logo: None,
            listing_scroll: false,
            tab: 0,
            detail: None,
            output: String::new(),
            pseudocode: String::new(),
            decompiling: None,
            status: "Ready. Open a thin ELF, PE or Mach-O binary.".into(),
            loading: None,
            name: String::new(),
            comment: String::new(),
            revision: 0,
            dark: true,
            tool: "binary_info".into(),
            args: "{}".into(),
        };
        if !result.path.is_empty() {
            result.load();
        }
        Ok(result)
    }
    fn load(&mut self) {
        if self.loading.is_some() {
            return;
        }
        let path = self.path.clone();
        let (tx, rx) = mpsc::channel();
        self.loading = Some(rx);
        self.status = "Analyzing binary…".into();
        std::thread::spawn(move || {
            let _ = tx.send(Analysis::open(path));
        });
    }
    fn set_function(&mut self, address: u64) -> bool {
        match self.ws.a().and_then(|a| a.function(address)) {
            Ok(detail) => {
                self.name = detail.function.name.clone();
                self.comment.clear();
                self.revision = 0;
                if let Some(a) = self.ws.analysis.as_ref() {
                    if let Ok(Some(ann)) = self.ws.store.annotation(a.workspace_id(), address) {
                        if let Some(name) = ann.name {
                            self.name = name;
                        }
                        self.comment = ann.comment.unwrap_or_default();
                        self.revision = ann.revision;
                    }
                }
                self.detail = Some(detail);
                true
            }
            Err(error) => {
                self.status = format!("{error:#}");
                false
            }
        }
    }
    fn move_cursor(&mut self, address: u64) -> bool {
        let Ok(analysis) = self.ws.a() else {
            return false;
        };
        let arm = analysis.architecture == "arm";
        let normalized = if arm { address & !1 } else { address };
        let functions = &analysis.functions;
        let exact = functions
            .binary_search_by_key(&address, |function| function.address)
            .ok();
        let index = functions.partition_point(|function| {
            (if arm {
                function.address & !1
            } else {
                function.address
            }) <= normalized
        });
        let function = exact
            .or_else(|| {
                index.checked_sub(1).filter(|index| {
                    let function = &functions[*index];
                    let start = if arm {
                        function.address & !1
                    } else {
                        function.address
                    };
                    normalized - start < function.size
                })
            })
            .map(|index| functions[index].address);
        if let Some(function) = function {
            let changed = self
                .detail
                .as_ref()
                .is_none_or(|detail| detail.function.address != function);
            if changed && !self.set_function(function) {
                return false;
            }
            if changed && self.decompiling.is_none() {
                self.pseudocode.clear();
            }
        } else if analysis.read_bytes(address, 1).is_ok() {
            self.detail = None;
            self.tab = HEX;
        } else {
            self.status = format!("Address {address:#x} is not backed by the open binary");
            return false;
        }
        self.cursor = Some(address);
        self.address = format!("{address:#x}");
        self.status = format!("Selected {address:#x}");
        self.listing_scroll = true;
        true
    }

    fn navigate(&mut self, address: u64) {
        let previous = self.cursor;
        if self.move_cursor(address) && previous != Some(address) {
            if let Some(previous) = previous {
                self.back.push(previous);
            }
            self.forward.clear();
        }
    }

    fn history(&mut self, back: bool) {
        let target = if back {
            self.back.last()
        } else {
            self.forward.last()
        }
        .copied();
        if let (Some(target), Some(current)) = (target, self.cursor) {
            if self.move_cursor(target) {
                if back {
                    self.back.pop();
                    self.forward.push(current);
                } else {
                    self.forward.pop();
                    self.back.push(current);
                }
            }
        }
    }

    fn reset_navigation(&mut self) {
        self.cursor = None;
        self.address.clear();
        self.back.clear();
        self.forward.clear();
        self.detail = None;
    }

    fn render_listing(&mut self, ui: &mut egui::Ui) {
        let Some(detail) = &self.detail else {
            ui.label("Select a function from the navigator.");
            return;
        };
        ui.heading(&self.name);
        ui.label(format!(
            "{:#x} · {} bytes · {} instructions",
            detail.function.address,
            detail.function.size,
            detail.instructions.len()
        ));
        let cursor = self.cursor;
        let selected_index = cursor.and_then(|address| {
            detail
                .instructions
                .iter()
                .rposition(|row| row.address <= address && address < row.end())
        });
        let mut go = None;
        let mut select = None;
        let mut scroll = egui::ScrollArea::both().id_salt("assembly");
        if self.listing_scroll {
            if let Some(index) = selected_index {
                scroll = scroll.vertical_scroll_offset(
                    (index as f32 * (22.0 + ui.spacing().item_spacing.y) - 60.0).max(0.0),
                );
            }
            self.listing_scroll = false;
        }
        scroll.show_rows(ui, 22.0, detail.instructions.len(), |ui, range| {
            for index in range {
                let row = &detail.instructions[index];
                ui.horizontal(|ui| {
                    let address = RichText::new(format!("{:016x}", row.address))
                        .monospace()
                        .color(workbench::address_tint(self.dark));
                    if ui
                        .selectable_label(Some(index) == selected_index, address)
                        .clicked()
                    {
                        select = Some(row.address);
                    }
                    ui.monospace(format!("{:<24}", row.bytes));
                    ui.monospace(RichText::new(format!("{:<10}", row.mnemonic)).strong());
                    if let Some(target) = row.target {
                        if ui.link(RichText::new(&row.operands).monospace()).clicked() {
                            go = Some(target);
                        }
                    } else {
                        ui.monospace(&row.operands);
                    }
                });
            }
        });
        if let Some(address) = go.or(select) {
            self.navigate(address);
        }
    }

    fn render_inspector(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.inspector_code, false, "References");
            ui.selectable_value(&mut self.inspector_code, true, "Pseudocode");
        });
        ui.separator();
        if self.inspector_code {
            self.render_pseudocode(ui);
            return;
        }
        let (Some(address), Ok(analysis)) = (self.cursor, self.ws.a()) else {
            ui.label("Select an address to see its references.");
            return;
        };
        ui.monospace(format!("{address:#018x}"));
        if let Some(detail) = &self.detail {
            ui.label(format!("{} · {} blocks", self.name, detail.blocks.len()));
        }
        ui.separator();
        let refs = analysis.xrefs(address);
        let outgoing = self
            .detail
            .as_ref()
            .and_then(|detail| {
                detail
                    .instructions
                    .iter()
                    .find(|instruction| instruction.address == address)
            })
            .and_then(|instruction| instruction.target);
        let mut jump = None;
        ui.strong("Outgoing target");
        if let Some(target) = outgoing {
            if ui.link(format!("{target:#x}")).clicked() {
                jump = Some(target);
            }
        } else {
            ui.label("No direct target at this address.");
        }
        ui.separator();
        ui.strong(format!("Incoming references · {}", refs.len()));
        egui::ScrollArea::vertical()
            .id_salt("raven-xrefs")
            .show_rows(ui, 22.0, refs.len(), |ui, range| {
                for index in range {
                    let reference = &refs[index];
                    if ui
                        .link(format!("{:#x}  {}", reference.from, reference.kind))
                        .clicked()
                    {
                        jump = Some(reference.from);
                    }
                }
            });
        if let Some(target) = jump {
            self.tab = LISTING;
            self.navigate(target);
        }
    }

    fn start_decompile(&mut self) {
        if let (Some(analysis), Some(detail)) = (&self.ws.analysis, &self.detail) {
            let address = detail.function.address;
            let analysis = analysis.clone();
            let (send, receive) = mpsc::channel();
            self.decompiling = Some(receive);
            self.pseudocode = format!("Decompiling {address:#x}…");
            std::thread::spawn(move || {
                let _ = send.send(raven::decompile::function(&analysis, address));
            });
        }
    }

    fn render_pseudocode(&mut self, ui: &mut egui::Ui) {
        let available = self.detail.is_some() && self.decompiling.is_none();
        if ui
            .add_enabled(available, egui::Button::new("Decompile selected function"))
            .clicked()
        {
            self.start_decompile();
        }
        if self.decompiling.is_some() {
            ui.spinner();
        }
        if self.pseudocode.is_empty() {
            ui.label("Configure RAVEN_GHIDRA_HOME to enable the Ghidra provider.");
        }
        egui::ScrollArea::both().show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(&self.pseudocode).monospace()).selectable(true));
        });
    }
    fn invoke(&mut self, tool: &str, args: Value) {
        match self.ws.call(tool, &args) {
            Ok(v) => {
                self.output = serde_json::to_string_pretty(&v).unwrap_or_default();
                self.status = format!("{tool}: complete");
                if matches!(tool, "open_raw" | "open_binary" | "close_binary") {
                    self.reset_navigation();
                    self.pseudocode.clear();
                    self.decompiling = None;
                    let first = self.ws.analysis.as_ref().and_then(|analysis| {
                        self.path = analysis.path.clone();
                        analysis.functions.first().map(|function| function.address)
                    });
                    if let Some(address) = first {
                        self.navigate(address);
                    }
                }
            }
            Err(e) => self.status = format!("{tool}: {e:#}"),
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.loading.is_none() {
            let dropped = ctx.input(|input| {
                input
                    .raw
                    .dropped_files
                    .iter()
                    .find_map(|file| file.path.clone())
            });
            if let Some(path) = dropped {
                self.path = path.to_string_lossy().into_owned();
                self.load();
            }
        }
        if !ctx.wants_keyboard_input()
            && self.detail.is_some()
            && ctx.input(|input| input.key_pressed(egui::Key::Space))
        {
            self.tab = if self.tab == GRAPH { LISTING } else { GRAPH };
            self.listing_scroll = self.tab == LISTING;
        }
        if let Some(worker) = &self.decompiling {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            match worker.try_recv() {
                Ok(result) => {
                    self.pseudocode = match result {
                        Ok(value) => format!(
                            "// Ghidra pseudocode for {}\n{}",
                            value["address"].as_str().unwrap_or_default(),
                            value["pseudocode"].as_str().unwrap_or_default()
                        ),
                        Err(error) => format!("{error:#}"),
                    };
                    self.decompiling = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pseudocode = "Decompiler worker disconnected".into();
                    self.decompiling = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.loading.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
            let received = self.loading.as_ref().unwrap().try_recv();
            match received {
                Ok(Ok(a)) => {
                    let first = a.functions.first().map(|f| f.address);
                    self.status = format!(
                        "{} · {} · {} function candidates",
                        a.format,
                        a.architecture,
                        a.functions.len()
                    );
                    self.ws.analysis = Some(a);
                    self.pseudocode.clear();
                    self.decompiling = None;
                    self.reset_navigation();
                    self.loading = None;
                    if let Some(first) = first {
                        self.navigate(first);
                    }
                }
                Ok(Err(e)) => {
                    self.status = format!("Open failed: {e:#}");
                    self.loading = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Analysis worker disconnected".into();
                    self.loading = None;
                }
                _ => {}
            }
        }
        ctx.set_visuals(if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(8.);
            ui.horizontal(|ui| {
                if let Some(logo) = &self.logo {
                    ui.image((logo.id(), egui::vec2(34.0, 34.0)));
                }
                ui.label(RichText::new("RAVEN Disassembler").strong().size(20.));
                ui.separator();
                if ui
                    .add_enabled(!self.back.is_empty(), egui::Button::new("Back"))
                    .clicked()
                {
                    self.history(true);
                }
                if ui
                    .add_enabled(!self.forward.is_empty(), egui::Button::new("Forward"))
                    .clicked()
                {
                    self.history(false);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut self.dark, "Dark theme");
                });
            });
            ui.add_space(8.);
            ui.horizontal(|ui| {
                ui.label("Binary path");
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .desired_width((ui.available_width() - 190.).max(160.)),
                );
                if ui
                    .add_enabled(self.loading.is_none(), egui::Button::new("Open binary"))
                    .clicked()
                {
                    self.load();
                }
                if ui
                    .add_enabled(self.ws.analysis.is_some(), egui::Button::new("Save report"))
                    .clicked()
                {
                    self.invoke(
                        "save_report",
                        json!({"path":format!("{}.raven.json",self.path)}),
                    );
                }
                if self.loading.is_some() {
                    ui.spinner();
                }
            });
            ui.add_space(8.);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(&self.status);
                ui.separator();
                ui.small("RAVEN 0.1 · independent engine · function extents may be inferred");
            });
        });
        egui::SidePanel::left("functions")
            .default_width(270.)
            .min_width(200.)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Functions");
                ui.label("Filter functions");
                ui.text_edit_singleline(&mut self.query);
                ui.separator();
                let renamed = self
                    .ws
                    .analysis
                    .as_ref()
                    .and_then(|a| self.ws.store.annotations(a.workspace_id()).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|ann| ann.name.map(|n| (ann.address, n)))
                    .collect::<std::collections::BTreeMap<_, _>>();
                let query = self.query.to_lowercase();
                let functions = self
                    .ws
                    .analysis
                    .as_ref()
                    .map(|a| {
                        a.functions
                            .iter()
                            .map(|f| {
                                (
                                    f.address,
                                    renamed
                                        .get(&f.address)
                                        .cloned()
                                        .unwrap_or_else(|| f.name.clone()),
                                    f.source.clone(),
                                )
                            })
                            .filter(|(_, name, _)| name.to_lowercase().contains(&query))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                ui.small(format!("{} candidates", functions.len()));
                egui::ScrollArea::vertical()
                    .id_salt("function-list")
                    .show_rows(ui, 25., functions.len(), |ui, range| {
                        for i in range {
                            let (addr, name, source) = &functions[i];
                            if ui
                                .selectable_label(
                                    self.detail
                                        .as_ref()
                                        .is_some_and(|d| d.function.address == *addr),
                                    format!("{addr:016x}  {name}"),
                                )
                                .on_hover_text(format!("Source: {source}"))
                                .clicked()
                            {
                                self.navigate(*addr);
                            }
                        }
                    });
            });
        egui::SidePanel::right("raven-inspector")
            .default_width(245.0)
            .min_width(190.0)
            .show(ctx, |ui| self.render_inspector(ui));
        egui::CentralPanel::default().show(ctx,|ui|{
            ui.horizontal_wrapped(|ui| {
                for (tab, label) in [
                    (LISTING, "Disassembly"), (GRAPH, "Control flow"), (HEX, "Hex bytes"),
                    (9, "Pseudocode"), (2, "Strings"), (3, "Sections"), (4, "Imports / exports"),
                    (6, "Metadata"), (5, "Triage"), (7, "Tools"), (8, "Coverage"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                        self.listing_scroll = tab == LISTING;
                        match tab {
                            5 => self.invoke("triage", json!({})),
                            6 => self.invoke("annotations", json!({})),
                            _ => {}
                        }
                    }
                }
            });
            ui.separator();
            if matches!(self.tab, LISTING | GRAPH | HEX) {
                ui.horizontal(|ui| {
                    ui.label("Virtual address");
                    let response = ui.text_edit_singleline(&mut self.address);
                    if ui.button("Go").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                        match parse_address(&self.address) {
                            Ok(address) => self.navigate(address),
                            Err(error) => self.status = error.to_string(),
                        }
                    }
                });
            }
            match self.tab{
                LISTING => self.render_listing(ui),
                GRAPH => {
                    if let Some(detail) = &self.detail {
                        if let Some(address) = workbench::graph_view(ui, detail, self.cursor, &mut self.graph_zoom) {
                            self.navigate(address);
                        }
                    } else {
                        ui.label("Select a function to see its control flow.");
                    }
                },
                HEX => {
                    if let (Some(address), Some(analysis)) = (self.cursor, &self.ws.analysis) {
                        if let Some(address) = workbench::hex_view(ui, analysis, address) {
                            self.navigate(address);
                        }
                    } else {
                        ui.label("Open a binary and select an address.");
                    }
                },
                2=>{ui.heading("Strings");ui.label("Search string content");ui.text_edit_singleline(&mut self.string_query);if let Some(a)=&self.ws.analysis{let rows=a.strings.iter().filter(|s|s.value.contains(&self.string_query)).collect::<Vec<_>>();egui::ScrollArea::both().show_rows(ui,22.,rows.len(),|ui,range|{for n in range{let s=rows[n];ui.monospace(format!("{:>18}  {}",s.address.map(|a|format!("{a:#x}")).unwrap_or_else(||format!("file+{:x}",s.file_offset)),s.value));}});}},
                3=>{ui.heading("Sections");if let Some(a)=&self.ws.analysis{egui::ScrollArea::both().show(ui,|ui|{egui::Grid::new("sections").striped(true).min_col_width(100.).show(ui,|ui|{for h in ["Name","Virtual address","Size","File offset","Entropy","Executable"]{ui.strong(h);}ui.end_row();for s in &a.sections{ui.label(&s.name);ui.monospace(format!("{:#x}",s.address));ui.label(s.size.to_string());ui.monospace(format!("{:#x}",s.file_offset));ui.label(format!("{:.3}",s.entropy));ui.label(if s.executable{"yes"}else{"no"});ui.end_row();}});});}},
                4=>{ui.heading("Imports / exports");if let Some(a)=&self.ws.analysis{egui::ScrollArea::both().show(ui,|ui|{ui.strong("Imports");for i in &a.imports{ui.monospace(format!("{}  {}",i.library,i.name));}ui.separator();ui.strong("Exports");for e in &a.exports{ui.monospace(format!("{:016x}  {}",e.address,e.name));}});}},
                5=>{ui.heading("Static triage");ui.label("String and entropy indicators are candidates; they do not establish malicious behavior.");if ui.button("Refresh triage").clicked(){self.invoke("triage",json!({}));}egui::ScrollArea::both().show(ui,|ui|{ui.monospace(&self.output);});},
                6=>{
                    ui.heading("Annotation workspace");ui.label("Selected virtual address");ui.monospace(&self.address);ui.label("Function name");ui.text_edit_singleline(&mut self.name);ui.label("Comment");ui.add(egui::TextEdit::multiline(&mut self.comment).desired_rows(4).desired_width(f32::INFINITY));
                    ui.horizontal(|ui|{if ui.add_enabled(self.detail.is_some(),egui::Button::new("Save revision")).clicked(){if let Some(address)=self.detail.as_ref().map(|detail| detail.function.address){match self.ws.call("annotate",&json!({"address":address,"name":self.name,"comment":self.comment,"author":"gui","expected_revision":self.revision})){Ok(v)=>{self.revision=v["revision"].as_u64().unwrap_or(0);self.status=format!("Annotation revision {} saved",self.revision);self.invoke("annotations",json!({}));},Err(e)=>self.status=format!("Save failed: {e:#}")}}}
if ui.button("Reload selected").clicked(){if let Some(a)=self.detail.as_ref().map(|detail| detail.function.address){self.set_function(a);}}
if ui.button("Audit history").clicked(){self.invoke("audit_log",json!({}));}});
                    egui::ScrollArea::both().show(ui,|ui|{ui.monospace(&self.output);});
                },
                7=>{
                    ui.heading("Analysis tools");ui.label("The same tool API is available through MCP and the headless CLI.");
                    egui::ComboBox::from_label("Tool").selected_text(&self.tool).show_ui(ui,|ui|{for t in raven::protocol::tools(){let n=t["name"].as_str().unwrap();if n!="assist"&&n!="run_plugin"&&n!="decompile_function"{ui.selectable_value(&mut self.tool,n.to_owned(),n);}}});
                    ui.label("Arguments (JSON object)");ui.add(egui::TextEdit::multiline(&mut self.args).code_editor().desired_rows(3).desired_width(f32::INFINITY));
                    if ui.button("Run tool").clicked(){match serde_json::from_str(&self.args){Ok(v)=>{let t=self.tool.clone();self.invoke(&t,v);},Err(e)=>self.status=format!("Invalid JSON: {e}")}}
                    egui::ScrollArea::both().show(ui,|ui|{ui.monospace(&self.output);});
                },
                9 => self.render_pseudocode(ui),
                _=>{ui.heading("Engine coverage");ui.label("Implemented: static inventory, x86/x64/ARM/AArch64 disassembly, direct control-flow xrefs, CFG, ASCII strings, annotations, exact function signatures, MCP stdio and process plugin SDK.");ui.add_space(12.);ui.label("Optional pseudocode provider: Ghidra. Remaining: debugger, full type recovery, data/indirect xrefs, unpacking/emulation, remote team synchronization, IDB compatibility and Hex-Rays plugin compatibility.");if let Some(a)=&self.ws.analysis{ui.separator();ui.monospace(&a.sha256);for l in &a.limitations{ui.label(format!("• {l}"));}}},
            }
        });
    }
}
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_default();
    let mut app = App::new(raven::default_database(), path)?;
    let icon = workbench::icon()?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon.clone())
            .with_inner_size([1440., 900.])
            .with_min_inner_size([960., 600.]),
        ..Default::default()
    };
    eframe::run_native(
        "RAVEN Disassembler",
        options,
        Box::new(|cc| {
            cc.egui_ctx.style_mut(|style| {
                style.spacing.item_spacing = egui::vec2(8., 8.);
                style
                    .text_styles
                    .insert(egui::TextStyle::Body, egui::FontId::proportional(14.));
                style
                    .text_styles
                    .insert(egui::TextStyle::Monospace, egui::FontId::monospace(13.));
            });
            let logo = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            app.logo = Some(cc.egui_ctx.load_texture(
                "raven-logo",
                logo,
                egui::TextureOptions::LINEAR,
            ));
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_tracks_branches_history_and_binary_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("branch.bin");
        // call 0x1006; ret; ret
        std::fs::write(&path, [0xe8, 1, 0, 0, 0, 0xc3, 0xc3]).unwrap();
        let mut app = App::new(PathBuf::from(":memory:"), String::new()).unwrap();
        app.invoke(
            "open_raw",
            json!({"path":path, "mode":"x86_64", "base":"0x1000"}),
        );
        assert_eq!(app.cursor, Some(0x1000));
        assert_eq!(
            app.detail.as_ref().unwrap().instructions[0].target,
            Some(0x1006)
        );
        app.navigate(0x1006);
        assert_eq!(app.detail.as_ref().unwrap().function.address, 0x1006);
        app.navigate(0xffff);
        assert_eq!(app.cursor, Some(0x1006));
        app.history(true);
        assert_eq!(app.cursor, Some(0x1000));
        app.history(false);
        assert_eq!(app.cursor, Some(0x1006));
        app.invoke("close_binary", json!({}));
        assert!(app.back.is_empty() && app.forward.is_empty() && app.cursor.is_none());
    }
}
