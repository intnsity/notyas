#!/usr/bin/env bash
# release.sh - tag and push notyas 0.1.0
# Run this from Windows (where the GPG key is) after all code fixes are committed.
#
# Prerequisites:
#   - the working tree is reachable (if it lives on a network share, mount it first)
#   - GitHub credentials configured (gh auth login or git credential helper)
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Tag the release
git tag -s v0.1.0 -m "notyas 0.1.0

Airgapped Bitcoin seed generator for ESP32-P4.

- Dice-based seed generation (RAW + FIXED modes, BIP39)
- Mnemonic display with reveal confirmation gate
- Optional passphrase (BIP39)
- BIP32/44/48/49/84/86 key derivation
- Receive addresses + account xpub with QR export
- On-device Verify screen (firmware SHA256, eFuse state, self-test)
- Verified on Waveshare 4B (720x720) and Elecrow 5inch (800x480)
- Stateless: no stored secrets, no radio, no TRNG
- Deterministic: user dice entropy only

Back button: navigates to prior screen with exit confirmation on
screens holding derived secrets. Passphrase Show/Hide toggle.
Build-graph check enforcing SECURITY.md invariants. Root Cargo workspace."

# Push everything
git push origin main
git push origin v0.1.0

echo "Release v0.1.0 pushed. Create a GitHub release from the tag."
