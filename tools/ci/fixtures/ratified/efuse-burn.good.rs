// The sanctioned form: the device refuses, and the operator runs the host ceremony.
//
// Q45 - the host CSPRNG is a trust dependency we can name and audit, and firmware that
// cannot burn an eFuse cannot brick a board through a bug or offer a glitch a path to
// steer. A mention of the ceremony in prose is not a call site, which is why this file
// names espefuse.py and the provisioning step without carrying either.

pub fn mount(provenance: KeyProvenance) -> Result<Vault, Error> {
    match provenance {
        KeyProvenance::EfuseReadProtected => Vault::open(),
        // Never provisioned: refuse. No wallet exists yet, nothing is lost, and the
        // operator runs the documented host step (docs/PROVISIONING.md). The only
        // irreversible step is the one they have not taken.
        _ => Err(Error::Unprovisioned),
    }
}
