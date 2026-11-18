//! Copy keys (`y` and friends) put a value on the clipboard directly, because
//! selecting it with the mouse is unreliable: long values wrap inside a
//! bordered box, so a drag picks up the border glyphs and a line break at
//! every wrap.
//!
//! On the machine wrustic runs on, the OS clipboard is written natively. That
//! works in every terminal, including macOS Terminal.app, which ignores the
//! OSC 52 clipboard escape. Over SSH the native clipboard belongs to the wrong
//! machine (or there is none), so the value goes to the terminal instead as
//! OSC 52, and the terminal on the user's side copies it — if it allows
//! applications clipboard access. Nothing reports whether it did, so the
//! notice says which path was taken rather than claiming success.

use std::io::Write;

use base64::Engine;

pub(crate) enum Copied {
    Native,
    Terminal,
}

#[derive(Default)]
pub(crate) struct Clipboard {
    /// Opened on first use, then kept: on X11 the clipboard is served by the
    /// process that owns it, so dropping the handle would drop the contents.
    native: Option<arboard::Clipboard>,
}

impl Clipboard {
    pub(crate) fn copy(&mut self, text: &str) -> std::io::Result<Copied> {
        if !over_ssh() {
            if self.native.is_none() {
                self.native = arboard::Clipboard::new().ok();
            }
            if let Some(native) = &mut self.native
                && native.set_text(text).is_ok()
            {
                return Ok(Copied::Native);
            }
        }
        let mut out = std::io::stdout().lock();
        out.write_all(osc52(text).as_bytes())?;
        out.flush()?;
        Ok(Copied::Terminal)
    }
}

fn over_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}

/// The OSC 52 "set clipboard" sequence, BEL-terminated (the terminator every
/// terminal that implements OSC 52 accepts).
fn osc52(text: &str) -> String {
    format!(
        "\x1b]52;c;{}\x07",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn osc52_carries_the_text_base64_encoded() {
        assert_eq!(super::osc52("snap-pw"), "\x1b]52;c;c25hcC1wdw==\x07");
    }
}
