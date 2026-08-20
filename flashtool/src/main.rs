// SPDX-License-Identifier: GPL-3.0-or-later
// notyas Flash Tool - verify and flash ESP32-P4 hardware wallet releases.
//
// A simple GUI tool that:
// 1. Verifies the GPG signature on downloaded release files
// 2. Verifies SHA256 hashes of each file
// 3. Detects the ESP32-P4 on a COM port
// 4. Flashes a merged.bin to the device via esptool
//
// Prerequisites (detected at runtime):
//   - GnuPG (gpg.exe) for signature verification
//   - Python + esptool for flashing (pip install esptool)

mod flash;
mod key;
mod verify;

use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;

const APP_NAME: &str = "notyas Flash Tool";
const WINDOW_W: f32 = 720.0;
const WINDOW_H: f32 = 560.0;

#[derive(Clone, PartialEq)]
enum Phase {
    Intro,
    Verify,
    Flash,
    Done,
}

#[derive(Clone, PartialEq)]
enum VerifyState {
    Idle,
    CheckingSig,
    CheckingHashes,
    Passed,
    Failed(String),
}

#[derive(Clone, PartialEq)]
enum FlashState {
    Idle,
    Flashing,
    Done,
    Failed(String),
}

#[derive(Clone)]
enum WorkMsg {
    Log(String),
    Done(bool, String),
}

struct App {
    phase: Phase,
    // tool availability
    gpg_path: Option<String>,
    esptool_path: Option<String>,
    // verify
    release_dir: Option<PathBuf>,
    sig_ok: bool,
    hashes_ok: bool,
    hash_results: Vec<(String, bool, String)>,
    verify_log: Vec<String>,
    verify_state: VerifyState,
    // flash
    ports: Vec<flash::PortInfo>,
    selected_port: Option<usize>,
    flash_file: Option<PathBuf>,
    flash_log: Vec<String>,
    flash_state: FlashState,
    // background work
    rx: Option<Receiver<WorkMsg>>,
    work_active: bool,
}

impl App {
    fn new() -> Self {
        Self {
            phase: Phase::Intro,
            gpg_path: verify::find_gpg(),
            esptool_path: flash::find_esptool(),
            release_dir: None,
            sig_ok: false,
            hashes_ok: false,
            hash_results: Vec::new(),
            verify_log: Vec::new(),
            verify_state: VerifyState::Idle,
            ports: Vec::new(),
            selected_port: None,
            flash_file: None,
            flash_log: Vec::new(),
            flash_state: FlashState::Idle,
            rx: None,
            work_active: false,
        }
    }

    fn refresh_ports(&mut self) {
        self.ports = flash::list_ports();
        // auto-select if exactly one port
        if self.ports.len() == 1 {
            self.selected_port = Some(0);
        } else {
            self.selected_port = None;
        }
    }

    fn drain_messages(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.rx {
            let mut work_done = false;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    WorkMsg::Log(line) => {
                        if self.phase == Phase::Verify {
                            self.verify_log.push(line);
                        } else {
                            self.flash_log.push(line);
                        }
                    }
                    WorkMsg::Done(success, message) => {
                        work_done = true;
                        if self.phase == Phase::Verify {
                            match self.verify_state {
                                VerifyState::CheckingSig => {
                                    if success {
                                        self.sig_ok = true;
                                        self.verify_log.push(
                                            "Signature verified - signed by the notyas release key.".to_string(),
                                        );
                                        self.verify_state = VerifyState::Idle;
                                    } else {
                                        self.verify_state = VerifyState::Failed(message);
                                    }
                                }
                                VerifyState::CheckingHashes => {
                                    if success {
                                        self.hashes_ok = true;
                                        self.verify_state = VerifyState::Passed;
                                    } else {
                                        self.verify_state = VerifyState::Failed(message);
                                    }
                                }
                                VerifyState::Idle | VerifyState::Passed | VerifyState::Failed(_) => {}
                            }
                        } else {
                            if success {
                                self.flash_state = FlashState::Done;
                                self.flash_log.push(message);
                            } else {
                                self.flash_state = FlashState::Failed(message);
                            }
                        }
                    }
                }
            }
            if work_done {
                self.work_active = false;
                self.rx = None;
            }
            if self.work_active {
                ctx.request_repaint();
            }
        }
    }

    fn start_verify_sig(&mut self) {
        let gpg = self.gpg_path.clone().unwrap();
        let dir = self.release_dir.clone().unwrap();
        let asc = dir.join("SHA256SUMS.txt.asc");
        let sums = dir.join("SHA256SUMS.txt");
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.work_active = true;
        self.verify_state = VerifyState::CheckingSig;
        self.verify_log.clear();
        self.verify_log.push("Checking GPG signature...".to_string());

        thread::spawn(move || {
            // First import the key
            if let Err(e) = verify::import_key(&gpg) {
                let _ = tx.send(WorkMsg::Log(format!("Key import note: {}", e)));
            }
            match verify::verify_signature(&gpg, &asc, &sums) {
                Ok(()) => {
                    let _ = tx.send(WorkMsg::Done(true, String::new()));
                }
                Err(e) => {
                    let _ = tx.send(WorkMsg::Done(false, e));
                }
            }
        });
    }

    fn start_verify_hashes(&mut self) {
        let dir = self.release_dir.clone().unwrap();
        let sums = dir.join("SHA256SUMS.txt");
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.work_active = true;
        self.verify_state = VerifyState::CheckingHashes;
        self.verify_log.push("Checking file hashes...".to_string());

        thread::spawn(move || {
            match verify::verify_hashes(&sums) {
                Ok(results) => {
                    let all_ok = results.iter().all(|(_, ok, _)| *ok);
                    for (name, ok, detail) in &results {
                        let mark = if *ok { "OK  " } else { "FAIL" };
                        let _ = tx.send(WorkMsg::Log(format!("{}  {}  {}", mark, name, detail)));
                    }
                    if all_ok {
                        let _ = tx.send(WorkMsg::Done(true, "All hashes match.".to_string()));
                    } else {
                        let fails = results.iter().filter(|(_, ok, _)| !ok).count();
                        let _ = tx.send(WorkMsg::Done(
                            false,
                            format!("{} file(s) failed hash verification.", fails),
                        ));
                    }
                }
                Err(e) => {
                    let _ = tx.send(WorkMsg::Done(false, e));
                }
            }
        });
    }

    fn start_flash(&mut self) {
        let esptool = self.esptool_path.clone().unwrap();
        let port = self.ports[self.selected_port.unwrap()].name.clone();
        let bin = self.flash_file.clone().unwrap();
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.work_active = true;
        self.flash_state = FlashState::Flashing;
        self.flash_log.clear();

        thread::spawn(move || {
            flash::flash_merged(&esptool, &port, &bin, tx);
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_messages(ctx);

        // Dark theme, slightly larger text
        ctx.set_visuals(egui::Visuals::dark());

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.phase {
                Phase::Intro => self.render_intro(ui),
                Phase::Verify => self.render_verify(ui),
                Phase::Flash => self.render_flash(ui),
                Phase::Done => self.render_done(ui),
            }
        });
    }
}

impl App {
    fn render_intro(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.heading(APP_NAME);
        ui.add_space(10.0);
        ui.label(
            "This tool verifies your notyas release files are authentic, then flashes\n\
             them to your ESP32-P4 board over USB.",
        );
        ui.add_space(15.0);

        // Prerequisites
        ui.label("Prerequisites checked:");
        ui.indent("prereqs", |ui| {
            let gpg_ok = &self.gpg_path;
            let et_ok = &self.esptool_path;
            ui.horizontal(|ui| {
                ui.label(if gpg_ok.is_some() { "[OK] " } else { "[MISSING] " });
                ui.label("GnuPG (for signature verification)");
            });
            ui.horizontal(|ui| {
                ui.label(if et_ok.is_some() { "[OK] " } else { "[MISSING] " });
                ui.label("esptool (for flashing)");
            });
            if gpg_ok.is_none() {
                ui.small("Install Gpg4win from https://gpg4win.org/download.html");
            }
            if et_ok.is_none() {
                ui.small("Install Python, then run: pip install esptool");
            }
        });

        ui.add_space(15.0);
        ui.label("You will need:");
        ui.indent("need", |ui| {
            ui.label("- Your downloaded release files (from the GitHub release page)");
            ui.label("- A USB-C cable (data, not charge-only)");
            ui.label("- Your ESP32-P4 board (Waveshare 4B or Elecrow 5)");
        });

        ui.add_space(20.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.gpg_path.is_some() && self.esptool_path.is_some(),
                    egui::Button::new("Start"),
                )
                .clicked()
            {
                self.phase = Phase::Verify;
            }
        });
    }

    fn render_verify(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Verify your download");
        ui.add_space(5.0);
        ui.label("Select the folder containing your downloaded release files.\n\
                 This should include SHA256SUMS.txt, SHA256SUMS.txt.asc, and the .bin files.");

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Select release folder...").clicked() {
                if let Some(dir) = rfd::FileDialog::new()
                    .set_title("Select release folder")
                    .pick_folder()
                {
                    self.release_dir = Some(dir);
                    self.sig_ok = false;
                    self.hashes_ok = false;
                    self.hash_results.clear();
                    self.verify_log.clear();
                    self.verify_state = VerifyState::Idle;
                }
            }
            if let Some(ref d) = self.release_dir {
                ui.label(d.display().to_string());
            }
        });

        ui.add_space(10.0);

        if self.release_dir.is_some() {
            // Check which files are present
            let dir = self.release_dir.as_ref().unwrap();
            let has_sums = dir.join("SHA256SUMS.txt").exists();
            let has_sums_asc = dir.join("SHA256SUMS.txt.asc").exists();

            ui.horizontal(|ui| {
                ui.label(if has_sums { "[OK] " } else { "[MISSING] " });
                ui.label("SHA256SUMS.txt");
            });
            ui.horizontal(|ui| {
                ui.label(if has_sums_asc { "[OK] " } else { "[MISSING] " });
                ui.label("SHA256SUMS.txt.asc (detached signature)");
            });

            ui.add_space(10.0);

            let can_verify = has_sums && has_sums_asc && !self.work_active;
            let can_hash = has_sums && self.sig_ok && !self.work_active;

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_verify, egui::Button::new("Verify signature"))
                    .clicked()
                {
                    self.start_verify_sig();
                }
                if self.sig_ok {
                    ui.label("  Signature OK");
                }
                if let VerifyState::Failed(ref msg) = self.verify_state {
                    ui.label(format!("  FAILED: {}", msg));
                }
            });

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_hash, egui::Button::new("Verify file hashes"))
                    .clicked()
                {
                    self.start_verify_hashes();
                }
                if self.hashes_ok {
                    ui.label("  All hashes match");
                }
            });

            // Log
            if !self.verify_log.is_empty() {
                ui.add_space(5.0);
                ui.label("Details:");
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        for line in &self.verify_log {
                            ui.label(
                                egui::RichText::new(line)
                                    .family(egui::FontFamily::Monospace)
                                    .small(),
                            );
                        }
                    });
            }

            ui.add_space(10.0);

            // Continue button
            let can_continue = self.sig_ok && self.hashes_ok;
            if ui
                .add_enabled(can_continue, egui::Button::new("Continue to Flash ->"))
                .clicked()
            {
                self.phase = Phase::Flash;
                self.refresh_ports();
            }
        }

        ui.add_space(10.0);
        if ui.button("< Back").clicked() {
            self.phase = Phase::Intro;
        }
    }

    fn render_flash(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 2: Flash your device");
        ui.add_space(5.0);

        // COM port detection
        ui.label("1. Plug in your ESP32-P4 board via USB-C.");
        ui.add_space(5.0);

        ui.horizontal(|ui| {
            if ui.button("Refresh ports").clicked() {
                self.refresh_ports();
            }
            if self.ports.is_empty() {
                ui.label("No COM ports detected. Plug in your board and click Refresh.");
            } else {
                ui.label(format!("{} port(s) found:", self.ports.len()));
            }
        });

        if !self.ports.is_empty() {
            ui.indent("ports", |ui| {
                for (i, port) in self.ports.iter().enumerate() {
                    let selected = self.selected_port == Some(i);
                    if ui
                        .selectable_label(selected, format!("{}  {}", port.name, port.description))
                        .clicked()
                    {
                        self.selected_port = Some(i);
                    }
                }
            });
        }

        ui.add_space(10.0);

        // Flash file selection
        ui.label("2. Select the merged.bin file for your board:");
        ui.horizontal(|ui| {
            if ui.button("Select merged.bin...").clicked() {
                if let Some(file) = rfd::FileDialog::new()
                    .set_title("Select merged.bin")
                    .add_filter("Binary", &["bin"])
                    .pick_file()
                {
                    self.flash_file = Some(file);
                }
            }
            // Auto-suggest from the verified release dir
            if let Some(ref dir) = self.release_dir {
                if ui.button("Use verified file").clicked() {
                    // Try to find a merged.bin in the release dir
                    if let Some(entry) = std::fs::read_dir(dir).ok().and_then(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .find(|e| {
                                e.file_name()
                                    .to_string_lossy()
                                    .contains("merged.bin")
                            })
                    }) {
                        self.flash_file = Some(entry.path());
                    }
                }
            }
        });
        if let Some(ref f) = self.flash_file {
            ui.label(format!("Selected: {}", f.display()));
        }

        ui.add_space(10.0);

        // Flash button
        let can_flash = self.selected_port.is_some()
            && self.flash_file.is_some()
            && !self.work_active;

        ui.horizontal(|ui| {
            if ui
                .add_enabled(can_flash, egui::Button::new("Flash"))
                .clicked()
            {
                self.start_flash();
            }
            match &self.flash_state {
                FlashState::Flashing => {
                    ui.label("Flashing... do not unplug!");
                }
                FlashState::Done => {
                    ui.label("Flash complete!");
                }
                FlashState::Failed(msg) => {
                    ui.label(format!("FAILED: {}", msg));
                }
                _ => {}
            }
        });

        // Flash log
        if !self.flash_log.is_empty() {
            ui.add_space(5.0);
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for line in &self.flash_log {
                        ui.label(
                            egui::RichText::new(line)
                                .family(egui::FontFamily::Monospace)
                                .small(),
                        );
                    }
                });
        }

        ui.add_space(10.0);
        if self.flash_state == FlashState::Done {
            if ui.button("Done ->").clicked() {
                self.phase = Phase::Done;
            }
        }
        if ui.button("< Back").clicked() {
            self.phase = Phase::Verify;
        }
    }

    fn render_done(&mut self, ui: &mut egui::Ui) {
        ui.add_space(40.0);
        ui.heading("Flash complete!");
        ui.add_space(15.0);
        ui.label("Your notyas device is flashed and ready.");
        ui.add_space(10.0);
        ui.label("You can now:");
        ui.indent("next", |ui| {
            ui.label("1. Unplug the USB cable");
            ui.label("2. Reconnect it to power on the device");
            ui.label("3. The Verify Device screen will appear on boot");
        });
        ui.add_space(20.0);
        if ui.button("Flash another device").clicked() {
            self.phase = Phase::Intro;
            self.flash_state = FlashState::Idle;
            self.flash_log.clear();
            self.flash_file = None;
            self.verify_log.clear();
            self.sig_ok = false;
            self.hashes_ok = false;
            self.hash_results.clear();
            self.verify_state = VerifyState::Idle;
            self.release_dir = None;
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WINDOW_W, WINDOW_H])
            .with_min_inner_size([WINDOW_W, WINDOW_H])
            .with_title(APP_NAME),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}
