// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-emits the ESP-IDF configuration flags, and refuses two configurations outright.
//!
//! The two refusals are ESP-SEAL.md 6.4 fence 2 and MILESTONES.md m4a's Q41 release
//! gate. Both exist because cargo feature unification means a transitive dependency can
//! turn a feature on without the application author noticing - a feature flag alone is
//! never the control. A build script failure is, because it cannot be unified away and
//! it stops the artefact from existing.

/// One respect in which a build either looks like a bench build or looks like a product.
///
/// Kept as data rather than folded into a single boolean expression because a refusal has
/// to print the whole table: the operator who hits this fence needs to see which property
/// gave the build away, and whoever edits the fence next needs to see what the other
/// properties said at the same moment.
struct Shape {
    /// The cargo variable read, named exactly, so a refusal can be reproduced by hand.
    var: &'static str,
    /// What cargo reported, or `<absent>`. Rendered, never parsed: it exists for the message.
    got: String,
    /// What a bench build reports, in the words the refusal prints.
    want: &'static str,
    /// True when this one respect looks like a bench build. Absence is never bench-shaped.
    bench: bool,
}

impl Shape {
    /// A cfg. Cargo exports one with an EMPTY value when it is on and not at all when it
    /// is off, so the test is presence and never the string - a `var()` comparison here
    /// would read every enabled cfg as the empty string and quietly answer "not that".
    fn cfg(var: &'static str, want: &'static str) -> Self {
        let present = std::env::var_os(var).is_some();
        Self {
            var,
            got: if present { "set" } else { "<absent>" }.to_string(),
            want,
            bench: present,
        }
    }

    /// A value, judged by `is_bench`. An absent variable is refused without the predicate
    /// being consulted at all: nothing that is not there can say this is a bench build.
    fn value(var: &'static str, want: &'static str, is_bench: fn(&str) -> bool) -> Self {
        match std::env::var(var) {
            Ok(v) => Self { var, bench: is_bench(&v), got: v, want },
            Err(_) => Self { var, got: "<absent>".to_string(), want, bench: false },
        }
    }
}

/// The answers as a block a refusal can quote, one property per line.
fn shape_table(shapes: &[Shape]) -> String {
    let mut out = String::new();
    for s in shapes {
        out.push_str(&format!(
            "      {:<26} = {:<9}  a bench build reports {:<24} {}\n",
            s.var,
            s.got,
            s.want,
            if s.bench { "ok" } else { "PRODUCT-SHAPED" },
        ));
    }
    out
}

fn main() {
    // CARGO_FEATURE_* rather than `cfg!(feature = ...)`: cargo documents the environment
    // variables, and a misspelled `cfg!` silently evaluates false forever - which is the
    // one failure mode a firewall cannot afford.
    let feature = |name: &str| std::env::var(format!("CARGO_FEATURE_{name}")).is_ok();
    let emulated_key = feature("UNSAFE_EMULATED_KEY");
    let hil_console = feature("HIL_CONSOLE");

    // WHAT "A PRODUCT IMAGE" MEANS HERE, AND WHY IT IS NOT ONE PROPERTY.
    //
    // This predicate has failed twice, in opposite directions, and both times it was a
    // single build-system property standing in for "what came out of rustc":
    //
    //   PROFILE == "release"        Cargo sets PROFILE from the inheritance ROOT and not
    //                               from the profile that was asked for, so a
    //                               `[profile.shipdev] inherits = "dev"` with opt-level 3,
    //                               lto on and debug assertions off reports PROFILE=debug.
    //                               A product-shaped image walked through because of how
    //                               its profile was named.
    //
    //   !CARGO_CFG_DEBUG_ASSERTIONS The repair for that, and worse. `[profile.hardened]
    //                               inherits = "release", debug-assertions = true` is
    //                               opt-level "s" with its debuginfo stripped and reports
    //                               that cfg as SET - so the console compiled in, this
    //                               script did not panic, and src/hil.rs's compile_error!
    //                               read the same single bit and stayed quiet with it. The
    //                               only thing "debug" about that image is a flag most
    //                               hardening guidance tells you to turn ON.
    //
    // The lesson is not that one of those variables was the wrong one to pick. It is that
    // each of them is one bit an author can set, and a fence one bit wide is a naming
    // convention. So the test is CONJUNCTIVE: a bench image must look like a bench image
    // in every respect cargo can report, and ANY product-shaped answer refuses the build.
    // The four below are independent - decided at different points, by different parts of
    // a profile - so no single flag can flip the verdict:
    //
    //   CARGO_CFG_DEBUG_ASSERTIONS  what rustc EMITS. Every debug_assert! and every
    //                               overflow-check panic path is in the image to be found,
    //                               which is what makes this a fact about the artefact.
    //   PROFILE                     where the profile is ROOTED. Refuses a release-rooted
    //                               profile whatever it turns back on afterwards.
    //   OPT_LEVEL                   how the code is TUNED. "s" is the level this repo's
    //                               product image is built at (workspace root
    //                               [profile.release]) and 3 is the other shipping level;
    //                               the bench profile is "z". A bench image must not be
    //                               tuned like the thing that ships.
    //   DEBUG                       whether the debuginfo an operator works with survived.
    //
    // Measured on cargo 1.96.0 with --features hil-console, against the real profile set
    // plus the four escapes, all read together:
    //
    //     dev           PROFILE=debug    OPT_LEVEL=z  DEBUG=true   assertions=set      accepted
    //     release       PROFILE=release  OPT_LEVEL=s  DEBUG=false  assertions=<absent> refused by 4
    //     hardened      PROFILE=release  OPT_LEVEL=s  DEBUG=false  assertions=set      refused by 3
    //     hardened-max  PROFILE=release  OPT_LEVEL=1  DEBUG=true   assertions=set      refused by 1
    //     shipdev       PROFILE=debug    OPT_LEVEL=3  DEBUG=false  assertions=<absent> refused by 3
    //     slimdev       PROFILE=debug    OPT_LEVEL=s  DEBUG=false  assertions=set      refused by 2
    //
    // `hardened-max` is the worst case and the reason PROFILE stays in the conjunction:
    // release-rooted with every bench-shaped bit cargo exports turned back on, it is
    // refused by that one property and by nothing else. `slimdev` is its mirror image -
    // dev-rooted, built at the product's own optimization level with its debuginfo thrown
    // away - and both of the previous fences accepted it.
    //
    // NOT USED, MEASURED RATHER THAN ASSUMED. CARGO_CFG_OVERFLOW_CHECKS reads like a fifth
    // conjunct and is not one: cargo does not export it. It is absent in the dev profile,
    // where overflow checks are on, and absent again with `overflow-checks = true` written
    // out longhand, so a fence that required it would refuse every bench build there is.
    // Rejected as well, an opt-in environment variable: that is a property of the
    // invocation rather than of the artefact - the same mistake one layer along - and it
    // would put the escape hatch in whatever shell ran the build, which on a release
    // machine is the one place nobody reviews.
    //
    // READ FAIL-CLOSED, IN EVERY CONJUNCT. A variable that is absent is refused before its
    // predicate is consulted, which is also what a future cargo that stopped exporting one
    // of these would produce. The direction is the whole point, and it is the sentence
    // this comment has carried since the first repair: this fence's failure mode must be a
    // bench build that will not compile, never a release image that does.
    let shapes = [
        Shape::cfg("CARGO_CFG_DEBUG_ASSERTIONS", "set"),
        Shape::value("PROFILE", "debug", |v| v == "debug"),
        Shape::value("OPT_LEVEL", "0, 1, 2 or z", |v| matches!(v, "0" | "1" | "2" | "z")),
        Shape::value("DEBUG", "not false/0/none", |v| {
            !matches!(v, "false" | "0" | "none")
        }),
    ];
    let product_image = shapes.iter().any(|s| !s.bench);
    let table = shape_table(&shapes);

    // Fence 2. `unsafe-emulated-key` substitutes a compiled-in constant for the
    // read-protected eFuse block. There is no environment override: the escape hatch is
    // to build a bench image, which is itself the visible signal that this is not a
    // product.
    if product_image && emulated_key {
        panic!(
            "notyas-firmware: feature `unsafe-emulated-key` is enabled in an image that is \
             not bench-shaped, i.e. a product image.\n\
             \n\
             That feature replaces the device-binding eFuse key with a constant compiled \
             into the image. Every wallet a device seals under it is protected by a key \
             that is published in this repository's source.\n\
             \n\
             This build reports:\n{table}\n\
             There is no override. A development image is a debug image: build in the dev \
             profile, or in one that is bench-shaped on every line above."
        );
    }

    // Q41. The HIL console can format the store, seal records, erase both partitions, print
    // ledger internals and SIGN a transaction over the serial port with no PIN. That is
    // exactly the command set a bench needs and exactly the one a shipped device must not
    // answer.
    //
    // This is the first of three layers and the only one that stops the artefact existing.
    // `src/hil.rs` carries the same rule as a `compile_error!` so it also holds when a build
    // script is skipped or stubbed, and `tools/ci/check-release-symbols.sh` reads the linked
    // ELF - because a build flag is a promise and only a symbol is evidence.
    if product_image && hil_console {
        panic!(
            "notyas-firmware: feature `hil-console` is enabled in an image that is not \
             bench-shaped, i.e. a product image.\n\
             \n\
             The test console drives the store from the UART with no PIN: it can format, \
             seal, wipe, dump raw flash and sign a transaction. A shipped image must not \
             contain it.\n\
             \n\
             This build reports:\n{table}\n\
             There is no override. Build the bench image in the dev profile, or in one \
             that is bench-shaped on every line above."
        );
    }

    // Layer 2's other half, and the only value this script hands to the code it guards.
    // `src/hil.rs` refuses to compile unless rustc's own `debug_assertions` is on AND this
    // cfg is set, so that layer sees the whole conjunction instead of sharing the single
    // bit that let `hardened` past both of them at once. It still holds when this script is
    // skipped or stubbed, and it now holds more tightly than before: the cfg being absent
    // is a refusal, so a stub that emits nothing fails the build rather than passing it.
    //
    // Emitted after the refusals on purpose. A build that is being rejected has said its
    // piece and must not also leave behind a cfg that reads as a verdict.
    println!("cargo::rustc-check-cfg=cfg(notyas_bench_image)");
    if !product_image {
        println!("cargo::rustc-cfg=notyas_bench_image");
    }

    // After the refusals, so a build that is going to be rejected is rejected before the
    // ESP-IDF environment is probed and re-emitted.
    embuild::espidf::sysenv::output();
}
