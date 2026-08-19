# SPDX-License-Identifier: MIT OR Apache-2.0
# notyas - the release build container.
#
# Permissively licensed on purpose: this file and tools/repro/build.sh are the
# first public reproducible-build recipe for the Rust + esp-idf-sys stack, and
# their whole value is that somebody else can paste them into their own
# repository without a licence audit. The rest of notyas is GPL-3.0-or-later.
#
# Build and run from the repository root:
#   docker build -t notyas-repro -f tools/repro/Dockerfile .
#   docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro waveshare-4b
#
# What this image pins, and why it is a container rather than a script:
# CONFIG_APP_REPRODUCIBLE_BUILD handles paths and timestamps inside the C build,
# but Espressif's own reproducible-builds page is explicit that the ESP-IDF
# version and the versions of CMake, Ninja and the cross-compiler are outside
# its reach, and names the IDF Docker image as the way to pin them. One digest
# pins all four, plus the Python that runs the component manager.
#
# The digest below is the pin that matters more than the tag; a tag is mutable.
# Re-read it at release time and record it in the release notes:
#   docker buildx imagetools inspect espressif/idf:v5.5.4
#
# A verifier who rebuilds this image may end up with different bytes than the
# maintainer's image (apt, rustup and crates.io all move). That is expected and
# harmless: every version that can change a byte of the firmware is pinned
# exactly below AND asserted at build time against tools/repro/toolchain.lock,
# so a drifted image fails the build loudly instead of producing a divergent
# artifact quietly.
FROM espressif/idf:v5.5.4@sha256:b9f2d6ea1c19e0c9f7959bdb74a9e3c775642f9d0f3b841937c5fa3363db892b

# espflash links against libudev for its serial half. Nothing here reaches the
# firmware image; the artifact path uses espflash's file-only subcommands.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libudev-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Rust, installed into the image rather than resolved at build time, so the
# toolchain is part of the artifact that gets pinned. rust-src is not optional:
# the tier-3 target riscv32imafc-esp-espidf needs -Zbuild-std, which compiles
# core, alloc and std from source here rather than downloading a prebuilt std.
# That is also why the standard library's paths matter to us at all
# (rust-lang/rust#73167) and why cargo trim-paths is passed in build.sh.
ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --no-modify-path \
                    --default-toolchain nightly-2026-07-27 \
                    --component rust-src \
 && rustc -vV

# Host tools that sit directly in the artifact path. Exact "=" pins, both
# recorded in toolchain.lock and asserted by build.sh before it compiles:
# espflash turns the ELF into app.bin and the CSV into partition-table.bin, and
# it has had image-layout bugs of exactly the kind that changes bytes.
RUN cargo install ldproxy  --version =0.3.5 --locked \
 && cargo install espflash --version =4.5.0 --locked

# bindgen's libclang. bindgen output differs across libclang versions - upstream
# keeps per-version expectation files - so this is a build input on par with the
# compiler. esp-clang is managed by ESP-IDF's own idf_tools.py, which means its
# version is pinned by the IDF release and therefore by this image's digest.
RUN . $IDF_PATH/export.sh \
 && python $IDF_PATH/tools/idf_tools.py install esp-clang

COPY tools/repro/build.sh tools/repro/toolchain.lock tools/repro/verify-manifest.py /opt/notyas/
RUN chmod 0755 /opt/notyas/build.sh

# No IDF entrypoint wrapper: build.sh activates ESP-IDF itself, after it has
# re-executed under a clean environment. Determinism belongs to the script, not
# to whatever the caller happened to have exported.
ENTRYPOINT ["/opt/notyas/build.sh"]
