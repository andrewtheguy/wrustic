const SERVICE: &str = "wrustic";

/// Installs the platform's native credential store as keyring-core's default.
///
/// Compiled out of a non-Windows test build: there `init_store` always picks
/// the mock, and nothing else may reach the machine's real credential store.
#[cfg(any(not(test), target_os = "windows"))]
fn init_native_store() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(store) = apple_native_keyring_store::keychain::Store::new() {
            keyring_core::set_default_store(store);
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(store) = dbus_secret_service_keyring_store::Store::new() {
            keyring_core::set_default_store(store);
            return true;
        }
    }
    // Windows Credential Manager (the "Generic Credentials" vault). Entries
    // land under a `wrustic.<instance>` target name and are readable only by
    // the logged-in user, same trust model as the macOS/Linux stores.
    #[cfg(target_os = "windows")]
    {
        if let Ok(store) = windows_native_keyring_store::Store::new() {
            keyring_core::set_default_store(store);
            return true;
        }
    }
    false
}

pub(crate) fn init_store() -> bool {
    // Under test this is keyring-core's in-memory mock, never the machine's
    // real store. A write against a locked macOS keychain or Secret Service
    // collection is answered with a GUI unlock prompt, which hangs an
    // unattended run of tests that have nothing to do with the keychain. The
    // mock keeps them on the same `Entry` API, with no prompt, no persistence
    // and no entry left in the developer's own credential store.
    #[cfg(test)]
    {
        // Installed once: a later call would swap in a fresh, empty mock and
        // drop whatever another test had already stored in it.
        static MOCK: std::sync::Once = std::sync::Once::new();
        MOCK.call_once(|| {
            keyring_core::set_default_store(
                keyring_core::mock::Store::new().expect("the in-memory mock store cannot fail"),
            );
        });
        true
    }
    #[cfg(not(test))]
    {
        init_native_store()
    }
}

pub(crate) fn save_passphrase(instance: &str, passphrase: &str) -> Result<(), String> {
    let entry =
        keyring_core::Entry::new(SERVICE, instance).map_err(|e| format!("keychain entry: {e}"))?;
    entry
        .set_password(passphrase)
        .map_err(|e| format!("keychain save: {e}"))
}

pub(crate) fn load_passphrase(instance: &str) -> Option<String> {
    let entry = keyring_core::Entry::new(SERVICE, instance).ok()?;
    entry.get_password().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard for every other test in this binary: whatever else a test
    /// touches, `init_store` must hand it the mock and never the machine's own
    /// credential store, or an unattended run can stall on an unlock dialog.
    #[test]
    fn tests_get_the_mock_store_not_the_real_one() {
        assert!(init_store(), "the mock store must always install");
        let vendor = keyring_core::get_default_store()
            .expect("init_store installs a default store")
            .vendor();
        assert!(
            vendor.contains("Mock store"),
            "tests must not reach a real credential store, got vendor: {vendor}"
        );

        // The same Entry API the production paths use, so the round-trip
        // covers the store actually being usable and not merely installed.
        let instance = format!("mock-{}", std::process::id());
        save_passphrase(&instance, "in-memory only").expect("save into the mock");
        assert_eq!(load_passphrase(&instance).as_deref(), Some("in-memory only"));
    }

    /// Round-trips a throwaway secret through Windows Credential Manager.
    ///
    /// Windows-only, because this is the one platform whose real store can be
    /// driven without a human at the screen: macOS and Linux answer a write
    /// against a locked keychain / Secret Service collection with a GUI unlock
    /// prompt, so the run either blocks on the dialog or is refused when no
    /// session can show one.
    ///
    /// `#[ignore]` because it writes to the real vault, and because that vault
    /// is reachable only from an interactive logon — run over a network logon
    /// (ssh, WinRM) every call fails with `ERROR_NO_SUCH_LOGON_SESSION`.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore]
    fn live_keychain_round_trip() {
        /// Deletes the test credential on unwind, so a failing assertion can't
        /// leave a stray entry behind in the user's real credential store.
        struct Cleanup(String);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Best-effort and deliberately silent: on the happy path the
                // test has already deleted the entry, so the expected outcome
                // here is a "no such credential" error. Panicking in Drop
                // during an unwind would abort the process and hide the real
                // failure.
                if let Ok(entry) = keyring_core::Entry::new(SERVICE, &self.0) {
                    let _ = entry.delete_credential();
                }
            }
        }

        // Not `init_store`: under test that installs the mock, and the whole
        // point here is the real vault.
        assert!(init_native_store(), "no native credential store available");
        let instance = format!("wrustic-test-{}", std::process::id());
        save_passphrase(&instance, "correct horse battery staple").expect("save");
        // Armed the moment the entry exists — every assertion below is now
        // covered whether it passes or panics.
        let _cleanup = Cleanup(instance.clone());
        assert_eq!(
            load_passphrase(&instance).as_deref(),
            Some("correct horse battery staple")
        );

        keyring_core::Entry::new(SERVICE, &instance)
            .expect("entry")
            .delete_credential()
            .expect("cleanup");
        assert!(load_passphrase(&instance).is_none(), "entry should be gone");
    }
}
