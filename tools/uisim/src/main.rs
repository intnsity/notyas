// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! uisim - render the notyas UI, and approve what it renders.
//!
//! Four subcommands, and the split between them is the whole design:
//!
//! - `tour` (the default) writes docs/screenshots/ui. A picture surface for humans.
//! - `approve` runs the bounds and coverage gates FIRST, refuses to write if either
//!   fails, and only then rewrites tools/uisim/goldens.txt and the pictures. It is the
//!   only thing in this repository that writes a golden.
//! - `manifest` PRINTS the manifest and writes nothing, so it can never bless anything.
//!   It is how goldens.txt is bootstrapped on a tree that still has known bounds defects,
//!   and it reports those defects on stderr first so nobody redirects it blind.
//! - `render <name> [--panel WxH]` writes one frame to target/uigate/ for a look.
//! - `diff` writes a before/after image per docs-tier frame to target/uigate/.
//!
//! `cargo test` never writes: tests/gate.rs is read-only by construction, so a failing
//! gate cannot be silenced by the act of running it.

use std::path::Path;

use uisim::catalog::{Frame, CATALOG, DOC_LANDSCAPE, DOC_PORTRAIT};
use uisim::gate;
use uisim::panel::{encode_png, SENTINEL};

use notyas_ui::layout::PANELS;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("tour");
    let rest: &[String] = if args.is_empty() { &[] } else { &args[1..] };
    match command {
        "tour" => tour(),
        "approve" => approve(),
        "manifest" => manifest(),
        "render" => render_one(rest),
        "diff" => diff(),
        other => {
            eprintln!("uisim: unknown command {other:?}");
            eprintln!(
                "usage: uisim [tour | approve | manifest | render <frame> [--panel WxH] | diff]"
            );
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------------------
// tour
// ---------------------------------------------------------------------------------------

/// Write every docs-tier frame, exactly as the 0.1.0 tour did.
///
/// Each frame is rendered TWICE and must match itself byte for byte before it is written:
/// that catches within-run nondeterminism here, and tools/ci/check-screenshots.sh catches
/// the across-machine kind by regenerating and diffing against the index.
fn tour() {
    let out_dir = gate::docs_path();
    std::fs::create_dir_all(&out_dir).expect("create output dir");
    println!("uisim: rendering the docs tier into {}", out_dir.display());
    println!(
        "sample data: BIP39 test vector #1 (64 sixes -> all-zero entropy, passphrase TREZOR)"
    );

    let mut written = 0usize;
    for (frame, panel, name) in docs_frames() {
        let render = || gate::render(frame, panel).1.png();
        let first = render();
        assert_eq!(first, render(), "{name}: non-deterministic render");
        let path = out_dir.join(format!("{name}.png"));
        std::fs::write(&path, &first).expect("write png");
        println!("  {} ({} bytes)", path.display(), first.len());
        written += 1;
    }
    println!("done: {written} pictures, each rendered twice and byte-identical");

    // A picture no frame produces any more is exactly the staleness these pictures exist
    // to avoid, and it is invisible to a regeneration that only ever overwrites.
    let known: Vec<String> = docs_frames().into_iter().map(|(_, _, n)| n).collect();
    for entry in std::fs::read_dir(&out_dir).expect("read output dir").flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "png") {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            if !known.contains(&stem) {
                println!("  orphan: {} is produced by no frame in the catalogue", path.display());
            }
        }
    }
}

/// The docs tier: every (frame, panel, filename) that becomes a committed picture.
fn docs_frames() -> Vec<(&'static Frame, (u32, u32), String)> {
    let mut out = Vec::new();
    for frame in CATALOG {
        for panel in [DOC_PORTRAIT, DOC_LANDSCAPE] {
            if let Some(name) = frame.doc.name_for(panel) {
                out.push((frame, panel, String::from(name)));
            }
        }
    }
    out.sort_by(|a, b| a.2.cmp(&b.2));
    out
}

// ---------------------------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------------------------

/// Bless the current pixels - but only the pixels.
///
/// The order is the policy. Bounds and coverage are checked before anything is written,
/// and a failure in either exits without touching a file, so the manifest can never record
/// a frame that draws off the panel or paper over a screen state that stopped rendering.
/// What lands in the commit is a goldens.txt diff, which IS the approval record: the
/// reviewer reads which frames moved and by how much in the ink, px and reg columns.
fn approve() {
    println!("uisim approve: rendering {} frames on {} panels ...", CATALOG.len(), PANELS.len());
    let rendered = gate::render_all();

    let escapes = gate::escape_failures(&rendered);
    let holes = gate::hole_failures(&rendered);
    let coverage = gate::coverage_failures(&rendered);
    let blocking: Vec<&String> = escapes.iter().chain(&holes).chain(&coverage).collect();
    if !blocking.is_empty() {
        eprintln!();
        eprintln!("REFUSING TO APPROVE - {} unapprovable failures", blocking.len());
        for line in blocking {
            eprintln!("  {line}");
        }
        eprintln!();
        eprintln!(
            "A frame that draws off its panel, leaves a panel pixel unpainted, or does not\n\
             exist is a defect, not a change. Fix the layout or the catalogue; there is no\n\
             flag that writes a golden over one of these."
        );
        std::process::exit(1);
    }

    let text = gate::manifest(&rendered);
    let path = gate::goldens_path();
    let previous = std::fs::read_to_string(&path).unwrap_or_default();
    std::fs::write(&path, &text).expect("write goldens.txt");
    let changed = gate::golden_failures(&text, &previous);
    println!("bounds: clean on all {} frames", rendered.len());
    println!("coverage: every declared screen state renders on all {} panels", PANELS.len());
    if previous.is_empty() {
        println!("wrote {} ({} lines, new file)", path.display(), rendered.len());
    } else if changed.is_empty() {
        println!("{}: unchanged", path.display());
    } else {
        println!("{}: {} frames changed", path.display(), changed.len());
        for line in changed.iter().take(40) {
            println!("  {line}");
        }
        if changed.len() > 40 {
            println!("  ... and {} more", changed.len() - 40);
        }
    }
    tour();
    println!();
    println!("approved. Commit tools/uisim/goldens.txt with the change that caused it.");
}

// ---------------------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------------------

/// Print the manifest. Writes nothing, anywhere.
///
/// The separation of powers this tool is built on is that only `approve` writes, and
/// `approve` refuses while a frame draws off the panel. That refusal is absolute, which
/// leaves one honest question: how does goldens.txt come into existence on a tree that
/// already has such a defect in a file the author is not fixing? Through here - a command
/// that can only print, whose output a person has to redirect themselves, and which names
/// every unapprovable failure on stderr before it prints a line. A pixel manifest never
/// blesses an escape in any case: escape and hole counts are deliberately not columns.
fn manifest() {
    let rendered = gate::render_all();
    let blocking: Vec<String> = gate::escape_failures(&rendered)
        .into_iter()
        .chain(gate::hole_failures(&rendered))
        .chain(gate::coverage_failures(&rendered))
        .collect();
    if !blocking.is_empty() {
        eprintln!("{} unapprovable failures stand in this tree:", blocking.len());
        for line in &blocking {
            eprintln!("  {line}");
        }
        eprintln!("They are NOT recorded below and are not made acceptable by it.");
        eprintln!();
    }
    print!("{}", gate::manifest(&rendered));
}

// ---------------------------------------------------------------------------------------
// render
// ---------------------------------------------------------------------------------------

fn render_one(args: &[String]) {
    let Some(name) = args.first() else {
        eprintln!("usage: uisim render <frame> [--panel WxH]");
        eprintln!("frames:");
        for f in CATALOG {
            eprintln!("  {}", f.name);
        }
        std::process::exit(2);
    };
    let Some(frame) = CATALOG.iter().find(|f| f.name == name) else {
        eprintln!("uisim: no frame named {name:?}. Run `uisim render` for the list.");
        std::process::exit(2);
    };
    let panel = match args.iter().position(|a| a == "--panel") {
        None => PANELS[0],
        Some(i) => {
            let spec = args.get(i + 1).map(String::as_str).unwrap_or("");
            let parsed = spec.split_once('x').and_then(|(w, h)| {
                Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?))
            });
            let Some(p) = parsed.filter(|p| PANELS.contains(p)) else {
                eprintln!("uisim: --panel wants one of {PANELS:?}, got {spec:?}");
                std::process::exit(2);
            };
            p
        }
    };
    let (_, target) = gate::render(frame, panel);
    let dir = work_dir();
    let path = dir.join(format!("{}-{}x{}.png", frame.name.replace('/', "-"), panel.0, panel.1));
    std::fs::write(&path, target.png()).expect("write png");
    let m = target.measure();
    println!("{} at {}x{} -> {}", frame.name, panel.0, panel.1, path.display());
    println!("  escapes: {}", target.escapes().describe());
    if target.escapes().count > 0 {
        let with_margins =
            dir.join(format!("{}-{}x{}.escaped.png", frame.name.replace('/', "-"), panel.0, panel.1));
        std::fs::write(&with_margins, target.png_with_margins()).expect("write escape png");
        println!("  what escaped, with the panel edge marked: {}", with_margins.display());
    }
    println!("  holes:   {}", m.holes.describe());
    println!("  ink:     {} px", m.ink_px);
}

// ---------------------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------------------

/// Before/after, for the tier where "before" actually exists.
///
/// The committed PNGs ARE the previous pixels for the docs frames, and this crate already
/// decodes PNG, so a true image diff costs a decode and a compare. For the matrix-only
/// frames there are no stored pixels BY DESIGN - committing about 275 PNGs would put
/// roughly 10 MB of binary churn in git on every layout change - so the honest way to see
/// the old one is `git stash && cargo run -p uisim -- render <name>`. That limitation is
/// documented rather than paid for.
fn diff() {
    let docs = gate::docs_path();
    let dir = work_dir();
    let mut changed_frames = 0;
    for (frame, panel, name) in docs_frames() {
        let stored = docs.join(format!("{name}.png"));
        let (_, target) = gate::render(frame, panel);
        let now = target.rgb888();
        let Some(before) = decode_rgb(&stored, panel) else {
            println!("{name}: no committed picture to compare against");
            continue;
        };
        let mut out = Vec::with_capacity(now.len());
        let mut changed = 0u32;
        for (a, b) in before.chunks_exact(3).zip(now.chunks_exact(3)) {
            if a == b {
                // Unchanged pixels at a quarter luminance: still legible as the frame, so
                // a reader can see WHERE the change is, never mistakable for the change.
                out.extend_from_slice(&[a[0] / 4, a[1] / 4, a[2] / 4]);
            } else {
                changed += 1;
                out.extend_from_slice(&sentinel_rgb());
            }
        }
        if changed == 0 {
            continue;
        }
        changed_frames += 1;
        let path = dir.join(format!("{name}.diff.png"));
        std::fs::write(&path, encode_png(panel.0, panel.1, &out)).expect("write diff png");
        println!("{name}: {changed} pixels changed -> {}", path.display());
    }
    if changed_frames == 0 {
        println!("diff: every committed picture matches what this tree renders");
    }
}

fn decode_rgb(path: &Path, panel: (u32, u32)) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let decoder = png::Decoder::new(std::io::BufReader::new(file));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.width != panel.0 || info.height != panel.1 || info.color_type != png::ColorType::Rgb {
        return None;
    }
    buf.truncate(info.buffer_size());
    Some(buf)
}

/// The sentinel as RGB888, so a changed pixel in a diff image is the same magenta the
/// hole check uses. One "this is wrong" colour across the whole instrument.
fn sentinel_rgb() -> [u8; 3] {
    use embedded_graphics::pixelcolor::RgbColor;
    let (r, g, b) = (SENTINEL.r(), SENTINEL.g(), SENTINEL.b());
    [(r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)]
}

/// `uigate/` inside the ACTIVE target directory - build output, never the repository.
///
/// Derived from this executable's own path rather than from `CARGO_MANIFEST_DIR`, because
/// the manifest path is a source location and says nothing about where cargo was told to
/// build. `.cargo/config.toml` pins `build.target-dir` off the working tree on purpose -
/// the tree is canonical on an SMB share, and build churn against that share is the
/// heaviest filesystem workload this project produces - and the old manifest-relative
/// walk resolved to `<repo>/target/uigate` regardless, writing tens of megabytes of PNGs
/// into the very directory the pin exists to keep empty. `tools/ci/check-target-dir.sh`
/// then failed on the artefacts, under a doc comment here that claimed the opposite.
///
/// The running binary always sits at `<target-dir>/<profile>/uisim`, so two levels up is
/// the target directory whatever `--target-dir`, `CARGO_TARGET_DIR` or the config said.
fn work_dir() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("uisim knows its own path");
    let target = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("<target-dir>/<profile>/uisim");
    let dir = target.join("uigate");
    std::fs::create_dir_all(&dir).expect("create <target-dir>/uigate");
    dir
}
