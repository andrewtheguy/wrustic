const SERVICE: &str = "wrustic";

pub(crate) fn save_passphrase(instance: &str, passphrase: &str) -> Result<(), String> {
    let entry =
        keyring::Entry::new(SERVICE, instance).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .set_password(passphrase)
        .map_err(|e| format!("keychain save: {e}"))
}

pub(crate) fn load_passphrase(instance: &str) -> Option<String> {
    let entry = keyring::Entry::new(SERVICE, instance).ok()?;
    entry.get_password().ok()
}
