use eframe::egui::{self, Color32, RichText};
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
    fn select(&mut self, address: u64) {
        self.address = format!("{address:#x}");
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
                self.status = format!("Selected {address:#x}");
            }
            Err(e) => self.status = format!("{e:#}"),
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
                    self.detail = None;
                    self.pseudocode.clear();
                    self.decompiling = None;
                    let first = self.ws.analysis.as_ref().and_then(|analysis| {
                        self.path = analysis.path.clone();
                        analysis.functions.first().map(|function| function.address)
                    });
                    if let Some(address) = first {
                        self.select(address);
                    }
                }
            }
            Err(e) => self.status = format!("{tool}: {e:#}"),
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                    self.detail = None;
                    self.loading = None;
                    if let Some(first) = first {
                        self.select(first);
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
                ui.label(RichText::new("RAVEN Disassembler").strong().size(22.));
                ui.separator();
                ui.label("Static analysis workbench");
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
                                self.select(*addr);
                            }
                        }
                    });
            });
        egui::CentralPanel::default().show(ctx,|ui|{
            ui.horizontal_wrapped(|ui|{for(i,name)in ["Disassembly","Control flow","Strings","Sections","Imports / exports","Triage","Metadata","Tools","Coverage","Pseudocode"].iter().enumerate(){if ui.selectable_label(self.tab==i,*name).clicked(){self.tab=i;if i==5{self.invoke("triage",json!({}));}
if i==6{self.invoke("annotations",json!({}));}}}});
            ui.separator();
            match self.tab{
                0=>{
                    ui.horizontal(|ui|{ui.label("Virtual address");ui.text_edit_singleline(&mut self.address);if ui.button("Go").clicked(){match parse_address(&self.address){Ok(a)=>self.select(a),Err(e)=>self.status=e.to_string()}}});
                    if let Some(d)=&self.detail{
                        ui.heading(&self.name);ui.label(format!("{:#x} · {} bytes · {} instructions · {} blocks",d.function.address,d.function.size,d.instructions.len(),d.blocks.len()));
                        let rows=&d.instructions;
                        egui::ScrollArea::both().id_salt("assembly").show_rows(ui,22.,rows.len(),|ui,range|{for index in range{let i=&rows[index];ui.horizontal(|ui|{ui.monospace(RichText::new(format!("{:016x}",i.address)).color(if self.dark{Color32::from_rgb(140,175,195)}else{Color32::from_rgb(45,75,95)}));ui.monospace(format!("{:<24}",i.bytes));ui.monospace(RichText::new(format!("{:<10}",i.mnemonic)).strong());ui.monospace(&i.operands);});}});
                    }else{ui.label("Open a binary and choose a function.");}
                },
                1=>{
                    ui.heading("Control flow");ui.label("Reachable basic blocks and direct successor addresses");
                    if let Some(d)=&self.detail{egui::ScrollArea::both().show(ui,|ui|{for block in &d.blocks{egui::Frame::group(ui.style()).show(ui,|ui|{ui.strong(format!("block_{:x}",block.address));for i in &block.instructions{ui.monospace(format!("{:x}  {} {}",i.address,i.mnemonic,i.operands));}ui.separator();ui.monospace(format!("Successors: {}",block.successors.iter().map(|s|format!("{s:#x}")).collect::<Vec<_>>().join(", ")));});ui.add_space(12.);}});}
                },
                2=>{ui.heading("Strings");ui.label("Search string content");ui.text_edit_singleline(&mut self.string_query);if let Some(a)=&self.ws.analysis{let rows=a.strings.iter().filter(|s|s.value.contains(&self.string_query)).collect::<Vec<_>>();egui::ScrollArea::both().show_rows(ui,22.,rows.len(),|ui,range|{for n in range{let s=rows[n];ui.monospace(format!("{:>18}  {}",s.address.map(|a|format!("{a:#x}")).unwrap_or_else(||format!("file+{:x}",s.file_offset)),s.value));}});}},
                3=>{ui.heading("Sections");if let Some(a)=&self.ws.analysis{egui::ScrollArea::both().show(ui,|ui|{egui::Grid::new("sections").striped(true).min_col_width(100.).show(ui,|ui|{for h in ["Name","Virtual address","Size","File offset","Entropy","Executable"]{ui.strong(h);}ui.end_row();for s in &a.sections{ui.label(&s.name);ui.monospace(format!("{:#x}",s.address));ui.label(s.size.to_string());ui.monospace(format!("{:#x}",s.file_offset));ui.label(format!("{:.3}",s.entropy));ui.label(if s.executable{"yes"}else{"no"});ui.end_row();}});});}},
                4=>{ui.heading("Imports / exports");if let Some(a)=&self.ws.analysis{egui::ScrollArea::both().show(ui,|ui|{ui.strong("Imports");for i in &a.imports{ui.monospace(format!("{}  {}",i.library,i.name));}ui.separator();ui.strong("Exports");for e in &a.exports{ui.monospace(format!("{:016x}  {}",e.address,e.name));}});}},
                5=>{ui.heading("Static triage");ui.label("String and entropy indicators are candidates; they do not establish malicious behavior.");if ui.button("Refresh triage").clicked(){self.invoke("triage",json!({}));}egui::ScrollArea::both().show(ui,|ui|{ui.monospace(&self.output);});},
                6=>{
                    ui.heading("Annotation workspace");ui.label("Selected virtual address");ui.monospace(&self.address);ui.label("Function name");ui.text_edit_singleline(&mut self.name);ui.label("Comment");ui.add(egui::TextEdit::multiline(&mut self.comment).desired_rows(4).desired_width(f32::INFINITY));
                    ui.horizontal(|ui|{if ui.add_enabled(self.detail.is_some(),egui::Button::new("Save revision")).clicked(){if let Ok(address)=parse_address(&self.address){match self.ws.call("annotate",&json!({"address":address,"name":self.name,"comment":self.comment,"author":"gui","expected_revision":self.revision})){Ok(v)=>{self.revision=v["revision"].as_u64().unwrap_or(0);self.status=format!("Annotation revision {} saved",self.revision);self.invoke("annotations",json!({}));},Err(e)=>self.status=format!("Save failed: {e:#}")}}}
if ui.button("Reload selected").clicked(){if let Ok(a)=parse_address(&self.address){self.select(a);}}
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
    let app = App::new(raven::default_database(), path)?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
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
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
