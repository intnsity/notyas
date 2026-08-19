# Release runbook (specimen)

**The release identity.** notyas releases are signed with the OpenPGP RSA-4096 key
`intnsity`:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

Secure Boot v2 on ESP32-P4 is a different key entirely and must use RSA-3072, never
ECDSA (ROM-broken on shipping silicon, Espressif AR2026-006). It does not exist yet and
0.2.0 does not burn it. Naming it here is a contrast, not a claim about who signs the
release, and the detector has to be able to tell those apart.
