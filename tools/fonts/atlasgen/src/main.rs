//! atlasgen - rasterizes the committed IBM Plex TTFs into static Rust glyph atlases.
//!
//! Input : tools/fonts/upstream/*.ttf (unmodified upstream files, committed)
//! Output: crates/notyas-fonts/src/gen/*.rs (one module per font+size, plus mod.rs)
//!
//! The output is deliberately reproducible: the glyph set is a fixed ordered list, all
//! metrics come from fontdue's deterministic rasterizer, nothing iterates a hash map
//! while emitting, and no timestamps or environment data are written. Running this
//! twice from the same TTFs produces byte-identical files (tools/fonts/regen.ps1).
//!
//! Licensing: the upstream faces are IBM Plex (OFL 1.1). "Plex" is a Reserved Font
//! Name, and these rasterized atlases are Modified Versions under OFL clause 3, so the
//! derived families are named "notyas Sans" and "notyas Mono". See LICENSE-fonts at
//! the repository root.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The fixed glyph set, identical to desktop BigDice's subset: printable ASCII
/// U+0020..=U+007E in codepoint order, then U+2022 (bullet) and U+2026 (ellipsis).
/// Index into this list is the index into every generated GLYPHS table.
const EXTRA: [char; 2] = ['\u{2022}', '\u{2026}'];
const GLYPH_COUNT: usize = 0x7F - 0x20 + EXTRA.len();

fn glyph_set() -> Vec<char> {
    (0x20u32..=0x7E)
        .map(|cp| char::from_u32(cp).unwrap())
        .chain(EXTRA)
        .collect()
}

struct Job {
    /// File name under tools/fonts/upstream/.
    ttf: &'static str,
    /// Upstream GitHub release tag the TTF came from (provenance, recorded in headers).
    release: &'static str,
    /// Derived family name (Reserved-Font-Name-safe).
    family: &'static str,
    /// Module-name prefix.
    ident: &'static str,
    /// Style name as emitted.
    style: &'static str,
    /// Pixel sizes to rasterize (em-relative px, the CSS/desktop-GUI sizing model).
    sizes: &'static [u32],
}

/// Target sizes for the 720x720 4" panel (~229 PPI): the desktop GUI's 15 px body text
/// scales by ~2.2x to hold physical size, giving ~32 px body; 44 px is the heading
/// step, 28 px the dense-mono step.
///
/// 24 px Sans Regular is the CAPTION step, added 2026-08-19. It is not a smaller body
/// size: it exists for controls that carry their own copy inside a target the page
/// cannot make taller - the wallet action cards get 62 px of inner height on the
/// 800x480 panel, which holds two 24 px lines and nothing larger. See
/// docs/plan-0.2.0/UX-SCREENS.md 0.5.
const JOBS: &[Job] = &[
    Job {
        ttf: "IBMPlexSans-Regular.ttf",
        release: "@ibm/plex-sans@1.1.0",
        family: "notyas Sans",
        ident: "sans",
        style: "Regular",
        sizes: &[24, 32],
    },
    Job {
        ttf: "IBMPlexSans-SemiBold.ttf",
        release: "@ibm/plex-sans@1.1.0",
        family: "notyas Sans",
        ident: "sans",
        style: "SemiBold",
        sizes: &[32, 44],
    },
    Job {
        ttf: "IBMPlexMono-Regular.ttf",
        release: "@ibm/plex-mono@2.5.0",
        family: "notyas Mono",
        ident: "mono",
        style: "Regular",
        sizes: &[28, 32],
    },
];

/// Font version string (name table ID 5), ASCII-sanitized for the generated headers.
fn font_version(data: &[u8]) -> String {
    let face = ttf_parser::Face::parse(data, 0).expect("ttf-parser: unparsable TTF");
    for name in face.names() {
        if name.name_id == ttf_parser::name_id::VERSION {
            if let Some(s) = name.to_string() {
                return s.chars().map(|c| if c.is_ascii() { c } else { '?' }).collect();
            }
        }
    }
    "unknown".to_string()
}

struct GlyphRec {
    ch: char,
    advance: u8,
    w: u8,
    h: u8,
    left: i8,
    top: i8,
    off: u32,
}

struct AtlasOut {
    module: String,
    statik: String,
    bitmap_bytes: usize,
    sample_width: u32,
}

fn checked_i8(v: i32, what: &str, ch: char) -> i8 {
    i8::try_from(v).unwrap_or_else(|_| panic!("{what}={v} out of i8 range for {ch:?}"))
}

fn checked_u8(v: usize, what: &str, ch: char) -> u8 {
    u8::try_from(v).unwrap_or_else(|_| panic!("{what}={v} out of u8 range for {ch:?}"))
}

fn generate(job: &Job, px: u32, upstream_dir: &Path, gen_dir: &Path) -> AtlasOut {
    let ttf_path = upstream_dir.join(job.ttf);
    let data = std::fs::read(&ttf_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", ttf_path.display()));
    let version = font_version(&data);

    // Fixed, explicit settings: FontSettings::default() spelled out so a fontdue
    // default change cannot silently alter the committed output.
    let font = fontdue::Font::from_bytes(
        data.as_slice(),
        fontdue::FontSettings {
            collection_index: 0,
            scale: 44.0,
            load_substitutions: true,
        },
    )
    .expect("fontdue: unparsable TTF");

    let set = glyph_set();
    let missing: Vec<char> = set
        .iter()
        .copied()
        .filter(|&c| font.lookup_glyph_index(c) == 0)
        .collect();
    assert!(missing.is_empty(), "{}: glyphs missing from font: {missing:?}", job.ttf);

    let lm = font
        .horizontal_line_metrics(px as f32)
        .expect("font has no horizontal line metrics");
    let ascent = lm.ascent.round() as i32;
    let descent = lm.descent.round() as i32; // negative
    let line_height = lm.new_line_size.round() as u32;

    let mut glyphs = Vec::with_capacity(GLYPH_COUNT);
    let mut bitmap: Vec<u8> = Vec::new();
    for &ch in &set {
        let (m, cov) = font.rasterize(ch, px as f32);
        assert_eq!(cov.len(), m.width * m.height, "coverage size mismatch for {ch:?}");
        let advance = m.advance_width.round();
        assert!((0.0..=255.0).contains(&advance), "advance {advance} for {ch:?}");
        let off = u32::try_from(bitmap.len()).expect("atlas exceeds u32 offsets");
        glyphs.push(GlyphRec {
            ch,
            advance: advance as u8,
            w: checked_u8(m.width, "width", ch),
            h: checked_u8(m.height, "height", ch),
            left: checked_i8(m.xmin, "left", ch),
            top: checked_i8(m.ymin + m.height as i32, "top", ch),
            off,
        });
        bitmap.extend_from_slice(&cov);
    }

    let module = format!("{}_{}_{}", job.ident, job.style.to_lowercase(), px);
    let statik = module.to_uppercase();

    let mut s = String::new();
    let w = &mut s;
    writeln!(w, "// GENERATED by tools/fonts/atlasgen - DO NOT EDIT.").unwrap();
    writeln!(w, "// Regenerate with tools/fonts/regen.ps1; output is byte-reproducible.").unwrap();
    writeln!(w, "//").unwrap();
    writeln!(w, "// {} {} {} px glyph atlas.", job.family, job.style, px).unwrap();
    writeln!(w, "// Derived from {} ({}, \"{}\"), SIL OFL 1.1.", job.ttf, job.release, version).unwrap();
    writeln!(w, "// \"Plex\" is a Reserved Font Name; this rasterized derivative is a Modified").unwrap();
    writeln!(w, "// Version and is therefore renamed \"{}\" per OFL clause 3.", job.family).unwrap();
    writeln!(w, "// Attribution and the full license: LICENSE-fonts at the repository root.").unwrap();
    writeln!(w, "//").unwrap();
    writeln!(w, "// Data layout:").unwrap();
    writeln!(w, "//   GLYPHS[i] describes glyph i of the fixed set: U+0020..=U+007E in codepoint").unwrap();
    writeln!(w, "//   order, then U+2022 (bullet) and U+2026 (ellipsis) - {} glyphs total.", GLYPH_COUNT).unwrap();
    writeln!(w, "//     advance: pen advance in px (font's fractional advance, rounded)").unwrap();
    writeln!(w, "//     w, h   : bitmap width/height in px (0 x 0 for blank glyphs like space)").unwrap();
    writeln!(w, "//     left   : bitmap left edge relative to the pen x (may be negative)").unwrap();
    writeln!(w, "//     top    : bitmap top edge in px above the baseline").unwrap();
    writeln!(w, "//     off    : byte offset of the glyph's pixels within BITMAP").unwrap();
    writeln!(w, "//   BITMAP holds w*h bytes per glyph, packed in set order with no padding:").unwrap();
    writeln!(w, "//   row-major, top row first, one byte per pixel, 8-bit alpha coverage").unwrap();
    writeln!(w, "//   (0 = fully background, 255 = fully ink).").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "use crate::{{Atlas, Glyph}};").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "pub static {statik}: Atlas = Atlas {{").unwrap();
    writeln!(w, "    family: \"{}\",", job.family).unwrap();
    writeln!(w, "    style: \"{}\",", job.style).unwrap();
    writeln!(w, "    px: {px},").unwrap();
    writeln!(w, "    ascent: {ascent},").unwrap();
    writeln!(w, "    descent: {descent},").unwrap();
    writeln!(w, "    line_height: {line_height},").unwrap();
    writeln!(w, "    glyphs: &GLYPHS,").unwrap();
    writeln!(w, "    bitmap: &BITMAP,").unwrap();
    writeln!(w, "}};").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "static GLYPHS: [Glyph; {GLYPH_COUNT}] = [").unwrap();
    for g in &glyphs {
        // {:?} on a char prints printable characters verbatim, which would leak the
        // non-ASCII bullet/ellipsis into the file; name those two instead.
        let label = match g.ch {
            '\u{2022}' => "bullet".to_string(),
            '\u{2026}' => "ellipsis".to_string(),
            c => format!("{c:?}"),
        };
        writeln!(
            w,
            "    Glyph {{ advance: {}, w: {}, h: {}, left: {}, top: {}, off: {} }}, // U+{:04X} {}",
            g.advance, g.w, g.h, g.left, g.top, g.off, g.ch as u32, label
        )
        .unwrap();
    }
    writeln!(w, "];").unwrap();
    writeln!(w).unwrap();
    writeln!(w, "static BITMAP: [u8; {}] = [", bitmap.len()).unwrap();
    for chunk in bitmap.chunks(32) {
        let line: Vec<String> = chunk.iter().map(|b| b.to_string()).collect();
        writeln!(w, "{},", line.join(",")).unwrap();
    }
    writeln!(w, "];").unwrap();

    assert!(s.is_ascii(), "non-ASCII leaked into generated {module}.rs");
    let out = gen_dir.join(format!("{module}.rs"));
    std::fs::write(&out, s.as_bytes()).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));

    let sample_width: u32 = "notyas 0.1.0"
        .chars()
        .map(|c| {
            let i = match c {
                ' '..='~' => c as usize - 0x20,
                '\u{2022}' => 95,
                '\u{2026}' => 96,
                _ => unreachable!(),
            };
            glyphs[i].advance as u32
        })
        .sum();

    AtlasOut { module, statik, bitmap_bytes: bitmap.len(), sample_width }
}

fn main() {
    // tools/fonts/atlasgen -> repo root is three levels up; paths are manifest-relative
    // so the tool is cwd-independent (regen.ps1 may be invoked from anywhere).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .nth(3)
        .expect("cannot locate repo root from CARGO_MANIFEST_DIR");
    let upstream_dir = root.join("tools").join("fonts").join("upstream");
    let gen_dir = root
        .join("crates")
        .join("notyas-fonts")
        .join("src")
        .join("gen");
    std::fs::create_dir_all(&gen_dir).expect("create gen dir");

    let mut outs = Vec::new();
    for job in JOBS {
        for &px in job.sizes {
            outs.push(generate(job, px, &upstream_dir, &gen_dir));
        }
    }

    // mod.rs: module list and a convenience roster, in generation order (fixed by JOBS).
    let mut m = String::new();
    writeln!(m, "// GENERATED by tools/fonts/atlasgen - DO NOT EDIT.").unwrap();
    writeln!(m, "// Regenerate with tools/fonts/regen.ps1. See sibling files for layout docs.").unwrap();
    writeln!(m).unwrap();
    for o in &outs {
        writeln!(m, "mod {};", o.module).unwrap();
    }
    writeln!(m).unwrap();
    for o in &outs {
        writeln!(m, "pub use {}::{};", o.module, o.statik).unwrap();
    }
    writeln!(m).unwrap();
    writeln!(m, "/// Every generated atlas, in generation order.").unwrap();
    writeln!(m, "pub static ALL: [&crate::Atlas; {}] = [", outs.len()).unwrap();
    for o in &outs {
        writeln!(m, "    &{},", o.statik).unwrap();
    }
    writeln!(m, "];").unwrap();
    assert!(m.is_ascii(), "non-ASCII leaked into generated mod.rs");
    std::fs::write(gen_dir.join("mod.rs"), m.as_bytes()).expect("write mod.rs");

    let total: usize = outs.iter().map(|o| o.bitmap_bytes).sum();
    println!("atlas                 bitmap bytes   width(\"notyas 0.1.0\")");
    for o in &outs {
        println!("{:<22}{:>12}   {:>6}", o.module, o.bitmap_bytes, o.sample_width);
    }
    println!("{:<22}{:>12}", "TOTAL", total);
}
