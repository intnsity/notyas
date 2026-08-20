// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The three-tier graphics gate, and the one policy that makes it worth having.
//!
//! Three obligations, in strictly decreasing severity:
//!
//! - **(a) Bounds.** No frame draws outside its panel, and no frame leaves a panel pixel
//!   unpainted. Measured by [`crate::panel::Panel`], which records what a display would
//!   discard. Never approvable: there is no layout change that legitimately paints off
//!   the glass.
//! - **(b) Coverage.** Every [`ScreenId`], in every state
//!   [`crate::catalog::required_variants`] declares, on every entry of
//!   [`notyas_ui::layout::PANELS`], renders and lands on the screen it claims. Never
//!   approvable: a missing frame is a missing frame.
//! - **(c) Pixels.** Every frame's digest matches the committed manifest. Approvable, and
//!   only through `uisim approve`, which is a deliberate act that leaves a reviewable
//!   diff behind.
//!
//! The policy: **approval runs (a) and (b) first and refuses to write if either fails.**
//! A developer can approve a pixel change and can never approve an out-of-bounds or
//! missing frame. That is the whole difference between this and "regenerate and commit",
//! which is a one-command auto-accept with no record of what was accepted.
//!
//! Escape and hole counts are deliberately NOT columns of the manifest. A column is a
//! value that can be re-blessed; these are invariants that abort the render.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use notyas_core::bitcoin::hashes::{sha256, Hash, HashEngine};
use notyas_ui::layout::{Rect, PANELS};
use notyas_ui::{ScreenId, Ui};

use crate::catalog::{build, required_variants, Doc, Frame, CATALOG};
use crate::panel::{Escape, Panel};

/// Marks the manifest's format so a change to the columns is an explicit act rather than
/// a silent reinterpretation of a committed file.
pub const FORMAT_TAG: &str = "# format: notyas-goldens/1";

/// One frame on one panel, measured.
pub struct Rendered {
    pub name: &'static str,
    pub variant: &'static str,
    pub screen: ScreenId,
    pub doc: Doc,
    pub panel: (u32, u32),
    /// Pixels drawn off the panel. Must be zero.
    pub escapes: Escape,
    /// Panel pixels nothing painted. Must be zero.
    pub holes: Escape,
    pub ink: Option<Rect>,
    pub ink_px: u32,
    pub digest: [u8; 32],
    /// How many tappable regions the screen offered, and a digest of their ids and
    /// rectangles. A touch target that moved without moving a pixel changes nothing a
    /// picture can show and everything about where a finger has to land.
    pub regions: usize,
    pub regions_digest: [u8; 4],
}

impl Rendered {
    /// This frame's line of the manifest. Fixed columns, ASCII, one line per
    /// (frame, panel), so a reviewer reads a layout change as text.
    pub fn golden_line(&self) -> String {
        let ink = match self.ink {
            None => String::from("-"),
            Some(r) => format!("{},{},{},{}", r.x, r.y, r.w, r.h),
        };
        format!(
            "{:<34} {:<9} {} ink={:<19} px={:<8} reg={}:{}",
            self.name,
            format!("{}x{}", self.panel.0, self.panel.1),
            hex(&self.digest[..8]),
            ink,
            self.ink_px,
            self.regions,
            hex(&self.regions_digest)
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render one catalogue frame on one panel and measure it.
pub fn render(frame: &Frame, panel: (u32, u32)) -> (Ui, Panel) {
    let ui = build(frame, panel);
    let mut target = Panel::new(panel.0, panel.1);
    ui.draw(&mut target).expect("draw into an infallible target");
    (ui, target)
}

/// The whole matrix: every frame on every shipped panel.
///
/// Ordered by (name, panel) so the manifest it produces is stable under a catalogue
/// reordering - a frame moved in the source must not rewrite the file.
pub fn render_all() -> Vec<Rendered> {
    let mut out = Vec::with_capacity(CATALOG.len() * PANELS.len());
    for frame in CATALOG {
        for panel in PANELS {
            let (ui, target) = render(frame, panel);
            let m = target.measure();
            let regions = ui.regions();
            let mut engine = sha256::Hash::engine();
            for r in &regions {
                engine.input(
                    format!("{:?} {} {} {} {}\n", r.id, r.rect.x, r.rect.y, r.rect.w, r.rect.h)
                        .as_bytes(),
                );
            }
            let rd = sha256::Hash::from_engine(engine).to_byte_array();
            out.push(Rendered {
                name: frame.name,
                variant: frame.variant,
                screen: frame.screen,
                doc: frame.doc,
                panel,
                escapes: target.escapes(),
                holes: m.holes,
                ink: m.ink,
                ink_px: m.ink_px,
                digest: m.digest,
                regions: regions.len(),
                regions_digest: [rd[0], rd[1], rd[2], rd[3]],
            });
        }
    }
    out.sort_by_key(|r| (r.name, r.panel.0, r.panel.1));
    out
}

/// The manifest text for a rendered matrix.
pub fn manifest(rendered: &[Rendered]) -> String {
    let mut out = String::new();
    out.push_str(FORMAT_TAG);
    out.push('\n');
    out.push_str("# One line per (frame, panel). Written only by `cargo run -p uisim -- approve`,\n");
    out.push_str("# which refuses to write while any frame draws off its panel or any declared\n");
    out.push_str("# screen state is missing. A diff here IS the approval record.\n");
    out.push_str("# columns: frame  panel  sha256[..8]  ink=x,y,w,h  px=<ink pixels>  reg=<count>:<digest>\n");
    for r in rendered {
        out.push_str(&r.golden_line());
        out.push('\n');
    }
    out
}

/// tools/uisim/goldens.txt - beside the catalogue that generates it, not in docs/, so
/// docs/screenshots stays the human picture surface.
pub fn goldens_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens.txt")
}

/// docs/screenshots/ui, resolved from this crate.
pub fn docs_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("screenshots")
        .join("ui")
}

// ---------------------------------------------------------------------------------------
// Tier (a): bounds
// ---------------------------------------------------------------------------------------

/// Frames that drew off their panel. Never approvable.
pub fn escape_failures(rendered: &[Rendered]) -> Vec<String> {
    rendered
        .iter()
        .filter(|r| r.escapes.count > 0)
        .map(|r| {
            format!(
                "{} at {}x{} drew {} outside the panel",
                r.name,
                r.panel.0,
                r.panel.1,
                r.escapes.describe()
            )
        })
        .collect()
}

/// Frames that left panel pixels unpainted. Never approvable.
pub fn hole_failures(rendered: &[Rendered]) -> Vec<String> {
    rendered
        .iter()
        .filter(|r| r.holes.count > 0)
        .map(|r| {
            format!(
                "{} at {}x{} left {} unpainted",
                r.name,
                r.panel.0,
                r.panel.1,
                r.holes.describe()
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Tier (b): coverage
// ---------------------------------------------------------------------------------------

/// Declared states with no frame, and frames declaring a state nobody declared.
///
/// Both directions on purpose. The first is the obligation; the second is typo
/// protection, without which a frame named `"no_word"` would satisfy nothing while
/// looking like it satisfied something.
pub fn coverage_failures(rendered: &[Rendered]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: BTreeMap<(&str, &str, (u32, u32)), usize> = BTreeMap::new();
    for r in rendered {
        *seen.entry((screen_slug(r.screen), r.variant, r.panel)).or_default() += 1;
    }
    for screen in ScreenId::ALL {
        for variant in required_variants(screen) {
            for panel in PANELS {
                if !seen.contains_key(&(screen_slug(screen), *variant, panel)) {
                    out.push(format!(
                        "no frame renders {:?} in state {:?} at {}x{}",
                        screen, variant, panel.0, panel.1
                    ));
                }
            }
        }
    }
    for frame in CATALOG {
        if !required_variants(frame.screen).contains(&frame.variant) {
            out.push(format!(
                "{} declares state {:?}, which required_variants({:?}) does not name",
                frame.name, frame.variant, frame.screen
            ));
        }
    }
    // The name is the manifest key and the argument to `uisim render`, so it has to say
    // which screen the line is about. Enforced rather than conventional: a mis-prefixed
    // name makes 295 sorted lines stop grouping by screen, which is the only thing that
    // makes the file readable as a diff.
    for frame in CATALOG {
        let want = format!("{}/", screen_slug(frame.screen));
        if !frame.name.starts_with(&want) {
            out.push(format!(
                "{} renders {:?}, so its name must start with {want:?}",
                frame.name, frame.screen
            ));
        }
    }
    // A duplicated frame name would make the manifest ambiguous and `uisim render <name>`
    // pick one of two frames at random.
    let mut names: Vec<&str> = CATALOG.iter().map(|f| f.name).collect();
    names.sort_unstable();
    for pair in names.windows(2) {
        if pair[0] == pair[1] {
            out.push(format!("two frames are named {:?}", pair[0]));
        }
    }
    out
}

/// A stable short name per screen, used only as a coverage key.
fn screen_slug(s: ScreenId) -> &'static str {
    match s {
        ScreenId::Home => "home",
        ScreenId::DiceEntry => "dice",
        ScreenId::MnemonicDisplay => "mnemonic",
        ScreenId::PhraseEntry => "phrase",
        ScreenId::PassphraseEntry => "passphrase",
        ScreenId::PassphraseUnlock => "passphrase-unlock",
        ScreenId::Deriving => "deriving",
        ScreenId::Schemes => "schemes",
        ScreenId::VerifyDevice => "verify-device",
        ScreenId::ScanningFlash => "scanning-flash",
        ScreenId::Lock => "lock",
        ScreenId::PinEntry => "pin",
        ScreenId::PinCreate => "pin-create",
        ScreenId::WalletList => "wallet-list",
        ScreenId::BackupCheck => "backup-check",
        ScreenId::KeepOrSave => "keep-or-save",
        ScreenId::NameWallet => "name-wallet",
        ScreenId::WalletHome => "wallet-home",
        ScreenId::EraseWallet => "erase-wallet",
        ScreenId::Settings => "settings",
        ScreenId::DeviceName => "device-name",
        ScreenId::AboutDeviceWords => "about-device-words",
        ScreenId::WipePolicy => "wipe-policy",
        ScreenId::SignSource => "sign-source",
        ScreenId::FilePicker => "file-picker",
        ScreenId::Working => "working",
        ScreenId::Refusal => "refusal",
        ScreenId::ReviewTransaction => "review-transaction",
        ScreenId::Signing => "signing",
        ScreenId::Deliver => "deliver",
        ScreenId::MultisigList => "multisig-list",
        ScreenId::MultisigImport => "multisig-import",
        ScreenId::MultisigDetail => "multisig-detail",
        ScreenId::FormatCard => "format-card",
    }
}

// ---------------------------------------------------------------------------------------
// Tier (c): the committed goldens
// ---------------------------------------------------------------------------------------

/// Per-field differences between the current matrix and the committed manifest.
///
/// The comparison is exact file equality; this is what produces a readable failure when
/// it does not hold. Localising the change to a field - the digest alone, or the digest
/// AND the ink box, or only the region digest - is what lets a reviewer decide whether a
/// change was intended without opening an image.
pub fn golden_failures(current: &str, committed: &str) -> Vec<String> {
    if current == committed {
        return Vec::new();
    }
    let parse = |text: &str| -> BTreeMap<String, Vec<String>> {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| {
                let mut f = l.split_whitespace().map(String::from);
                let name = f.next()?;
                let panel = f.next()?;
                let rest: Vec<String> = f.collect();
                Some((format!("{name} {panel}"), rest))
            })
            .collect()
    };
    let (now, was) = (parse(current), parse(committed));
    let mut out = Vec::new();

    if committed.lines().next() != Some(FORMAT_TAG) {
        out.push(format!(
            "goldens.txt is not {FORMAT_TAG:?}; the committed manifest is a different format"
        ));
    }
    for key in was.keys() {
        if !now.contains_key(key) {
            out.push(format!("{key}: in goldens.txt, not rendered any more"));
        }
    }
    for (key, fields) in &now {
        match was.get(key) {
            None => out.push(format!("{key}: rendered, not in goldens.txt")),
            Some(old) if old != fields => {
                let names = ["sha256", "ink", "px", "regions"];
                let mut deltas = Vec::new();
                for (i, name) in names.iter().enumerate() {
                    let (a, b) = (old.get(i), fields.get(i));
                    if a != b {
                        deltas.push(format!(
                            "{name} {} -> {}",
                            a.map(String::as_str).unwrap_or("-"),
                            b.map(String::as_str).unwrap_or("-")
                        ));
                    }
                }
                out.push(format!("{key}: {}", deltas.join(", ")));
            }
            Some(_) => {}
        }
    }
    if out.is_empty() {
        // Equal line by line but not byte for byte: a header or whitespace change.
        out.push(String::from(
            "goldens.txt differs from the rendered manifest in its header or whitespace only",
        ));
    }
    out
}

// ---------------------------------------------------------------------------------------
// Keeping PANELS married to the firmware
// ---------------------------------------------------------------------------------------

/// Every `(DISPLAY_WIDTH, DISPLAY_HEIGHT)` pair declared under `firmware/src/board`.
///
/// A hand-rolled line scan rather than a regex dependency: the shape being matched is
/// `pub const DISPLAY_WIDTH: u32 = 800;` and the whole grammar is "the integer before the
/// semicolon". notyas-ui cannot depend on the firmware crate - different target, different
/// toolchain - so this scan is the only mechanism that can keep
/// [`notyas_ui::layout::PANELS`] married to the boards that ship.
pub fn board_panels() -> Vec<(u32, u32)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("firmware")
        .join("src")
        .join("board");
    let mut out = Vec::new();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no board files under {}", dir.display());
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read board file");
        let value = |konst: &str| -> Option<u32> {
            text.lines()
                .map(str::trim)
                .find(|l| l.starts_with("pub const ") && l.contains(konst) && l.contains('='))
                .and_then(|l| l.rsplit('=').next())
                .map(|v| v.trim().trim_end_matches(';').trim())
                .and_then(|v| v.parse().ok())
        };
        if let (Some(w), Some(h)) = (value("DISPLAY_WIDTH"), value("DISPLAY_HEIGHT")) {
            out.push((w, h));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}
