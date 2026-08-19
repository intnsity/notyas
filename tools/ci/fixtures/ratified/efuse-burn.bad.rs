// Q45: release firmware contains no eFuse-burn code at all. This is the shape the defect
// would take - a burn on the first-save path, ungated, which is what ARCHITECTURE 2.2
// described before Q45 amended it.

pub fn first_save(key: &[u8; 32]) -> Result<(), Error> {
    let witness = Irreversible::i_understand();
    provisioning::burn_hmac_up_key(KeyBlock::Key0, key, witness)?;
    Ok(())
}
