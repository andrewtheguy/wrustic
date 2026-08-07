// Filenames as restic stores them, versus filenames as a client sees them.
//
// restic marshals every node name through Go's `strconv.Quote` and unmarshals
// it through `strconv.Unquote` (restic `internal/data/node.go`, `MarshalJSON`).
// So a name in a repository is *quoted*: a real EN SPACE (U+2002) is stored as
// the six-character unicode escape for it, a real backslash is stored doubled,
// and a byte that is not valid UTF-8 is stored as a hex escape.
//
// `rustic_core::repofile::Node::name()` reverses that — on Unix. Its Windows
// build defines `unescape_filename` as the identity function (see
// `rustic_core`'s `src/backend/node.rs`), so there the quoted form leaks
// through to the caller. That is not a cosmetic problem for an SMB share: the
// quoted form of a very ordinary macOS filename contains a backslash, SMB2
// filenames cannot, and the Windows redirector answers a directory listing
// carrying one by rejecting the *whole response* — every file in the directory
// disappears behind "the specified server cannot perform the requested
// operation". One quoted name makes one directory unbrowsable.
//
// So the share does not use that accessor at all. It reads `Node.name`, the
// raw stored spelling, and converts it here — `from_repo` on the way out to a
// client, `to_repo` on the way back in for a lookup, unconditionally on every
// platform. Working from the stored string is what makes that safe: there is
// nothing to double-decode, and a share behaves the same wherever it runs
// rather than inheriting a dependency's platform split.

use std::fmt::Write;

/// Decode a name as the repository stores it, into the name a client should
/// see.
///
/// Guarantees `to_repo(from_repo(stored)) == stored` for every name that
/// decodes: one this module cannot re-encode exactly is handed back untouched
/// rather than half-decoded, so a lookup built from the result finds the node
/// again. A name that does not decode still contains its backslash, so it never
/// reaches a client intact anyway — `backing::wire_safe` replaces the character
/// SMB cannot carry, and the file is listed but not openable.
pub(crate) fn from_repo(stored: &str) -> String {
    match decode(stored) {
        // The round-trip is the whole safety argument, so it is checked rather
        // than reasoned about: `encode` mirrors Go's `strconv.Quote` only for
        // the escapes it knows, and a name quoted for a reason it does not
        // model (an unassigned code point, a format character) would otherwise
        // decode to something that can never be looked up again.
        Some(decoded) if encode(&decoded) == stored => decoded,
        _ => stored.to_string(),
    }
}

/// Re-encode a decoded name into the form the repository stores.
pub(crate) fn to_repo(name: &str) -> String {
    encode(name)
}

/// Go `strconv.Unquote`, minus the surrounding quotes. `None` for input this
/// cannot decode: an escape restic would never write, a truncated one, or a
/// hex-escape run that does not add up to valid UTF-8.
fn decode(s: &str) -> Option<String> {
    if !s.contains('\\') {
        return Some(s.to_string());
    }
    // Bytes rather than chars: a hex escape addresses a byte, and several of
    // them in a row are how one non-ASCII character survives quoting.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next()? {
            '\\' => out.push(b'\\'),
            '"' => out.push(b'"'),
            // `\'` and `` \` `` are not decoded: Go's `strconv.Quote` escapes
            // only the backslash, the double quote and non-printables, so
            // restic never writes them. Accepting them would decode a name
            // restic could not have produced, and the round-trip check in
            // `from_repo` would reject the result anyway.
            'a' => out.push(0x07),
            'b' => out.push(0x08),
            'f' => out.push(0x0c),
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            'v' => out.push(0x0b),
            'x' => out.push(hex(&mut chars, 2)? as u8),
            'u' => push_char(&mut out, hex(&mut chars, 4)?)?,
            'U' => push_char(&mut out, hex(&mut chars, 8)?)?,
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

/// Read exactly `n` hex digits. Short input or a non-hex digit is a decode
/// failure, not a shorter number.
fn hex(chars: &mut std::str::Chars<'_>, n: usize) -> Option<u32> {
    let mut v: u32 = 0;
    for _ in 0..n {
        v = v * 16 + chars.next()?.to_digit(16)?;
    }
    Some(v)
}

fn push_char(out: &mut Vec<u8>, code: u32) -> Option<()> {
    let c = char::from_u32(code)?;
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Some(())
}

/// Go `strconv.Quote`, minus the surrounding quotes.
fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\u{7}' => out.push_str(r"\a"),
            '\u{8}' => out.push_str(r"\b"),
            '\u{c}' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\u{b}' => out.push_str(r"\v"),
            // Go writes a two-digit hex escape below U+0080, and a four- or
            // eight-digit unicode escape above it.
            c if (c as u32) < 0x80 && !is_printable(c) => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if !is_printable(c) => {
                let _ = if (c as u32) <= 0xFFFF {
                    write!(out, "\\u{:04x}", c as u32)
                } else {
                    write!(out, "\\U{:08x}", c as u32)
                };
            }
            c => out.push(c),
        }
    }
    out
}

/// Go's `unicode.IsPrint`, near enough.
///
/// Go prints letters, marks, numbers, punctuation and symbols, plus the ASCII
/// space — and quotes everything else, which is the C and Z categories. Rust's
/// standard library exposes no general-category table, so this reads the two
/// properties it does expose. The gap is the part of category C that is neither
/// a control character nor whitespace (format characters like U+200B, and
/// unassigned code points); a name quoted for one of those fails the round-trip
/// check in `from_repo` and is left alone, which is why the approximation is
/// safe rather than merely close.
fn is_printable(c: char) -> bool {
    c == ' ' || !(c.is_control() || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How restic stores a name containing one EN SPACE. Built rather than
    /// written out, so that the six characters cannot be mistaken for — or
    /// silently replaced by — the one character they stand for.
    fn quoted(prefix: &str, suffix: &str) -> String {
        format!("{prefix}\\u2002{suffix}")
    }

    /// The names that motivated the module: what a Mac snapshot actually holds.
    #[test]
    fn decodes_what_restic_quoted() {
        // Verified against restic 0.19.1: a file named with an EN SPACE is
        // stored as exactly this.
        assert_eq!(
            decode(&quoted("No.", "03-1532.pdf")).unwrap(),
            "No.\u{2002}03-1532.pdf"
        );
        assert_eq!(decode(&quoted("a", "b.txt")).unwrap(), "a\u{2002}b.txt");
        assert_eq!(decode(r"back\\slash").unwrap(), r"back\slash");
        assert_eq!(decode("quote\\\"d").unwrap(), "quote\"d");
        assert_eq!(decode(r"tab\there").unwrap(), "tab\there");
        assert_eq!(decode(r"emoji\U0001f600").unwrap(), "emoji\u{1f600}");
        // A character that needs no quoting arrives verbatim, as the CJK names
        // in a real repository do.
        assert_eq!(
            decode("\u{5f71}\u{97f3}.pdf").unwrap(),
            "\u{5f71}\u{97f3}.pdf"
        );
    }

    #[test]
    fn encode_is_the_inverse_of_decode() {
        let en_space = quoted("No.", "03-1532. - YI TU LIAN v.pdf");
        let nbsp = "nbsp\\u00a0gap".to_string();
        for stored in [
            en_space.as_str(),
            nbsp.as_str(),
            r"back\\slash",
            "quote\\\"d",
            r"tab\there",
            r"newline\nhere",
            r"bell\a",
            "plain.txt",
            "\u{5f71}\u{97f3}.pdf",
            "spaces are printable.txt",
        ] {
            let decoded = decode(stored).unwrap_or_else(|| panic!("{stored:?} decodes"));
            assert_eq!(encode(&decoded), stored, "round trip for {stored:?}");
        }
    }

    /// Both directions convert on every platform.
    ///
    /// This module once gated them behind `cfg!(windows)`, which left a share
    /// hosted on Linux or macOS serving the quoted name: listed with its
    /// backslash replaced, and impossible to open. The round-trip tests cannot
    /// catch that — with the gate in place both directions are the identity, so
    /// the round trip holds trivially — and no Windows run can catch it either.
    /// `.github/workflows/unix-ci.yml` exists to run this one.
    #[test]
    fn conversion_is_not_platform_conditional() {
        let stored = quoted("No.", "03-1532.pdf");
        let shown = "No.\u{2002}03-1532.pdf";
        assert_eq!(
            from_repo(&stored),
            shown,
            "from_repo must decode the stored spelling on every platform"
        );
        assert_eq!(
            to_repo(shown),
            stored,
            "to_repo must produce the stored spelling on every platform"
        );
    }

    /// The invariant every lookup depends on: whatever name a client is shown,
    /// re-encoding it names the same node in the repository.
    #[test]
    fn to_repo_undoes_from_repo() {
        let en_space = quoted("No.", "03-1532. - YI TU LIAN v.pdf");
        for stored in [
            en_space.as_str(),
            r"back\\slash",
            "quote\\\"d",
            r"tab\there",
            "plain.txt",
            "with space.txt",
            "\u{5f71}\u{97f3}.pdf",
        ] {
            assert_eq!(
                to_repo(&from_repo(stored)),
                stored,
                "round trip for {stored:?}"
            );
        }
    }

    /// A name this module cannot re-encode is passed through, not guessed at.
    ///
    /// It keeps its backslash, so `backing::wire_safe` replaces that before it
    /// reaches a client and the file cannot be opened through the share — but a
    /// half-decoded name would have been just as unopenable *and* wrong, and
    /// would have taken the rest of the directory with it.
    #[test]
    fn names_that_cannot_be_re_encoded_are_passed_through() {
        for stored in [
            // Decodable, but Go's quoting of U+200B (a format character) is
            // outside what `is_printable` models.
            "zero\\u200bwidth",
            // Would decode, but restic would never have written it: an emoji
            // is printable, so it is stored as itself.
            r"emoji\U0001f600",
            // Not decodable at all: an escape restic does not write, a
            // truncated one, a trailing backslash.
            r"not\qan\escape",
            r"truncated\u20",
            r"trailing\",
        ] {
            assert_eq!(from_repo(stored), stored, "passed through: {stored:?}");
        }
    }

    #[test]
    fn undecodable_names_are_left_alone() {
        // Not a decode failure to paper over: this is what a name looks like
        // when it was never quoted at all, and mangling it would lose the file.
        assert_eq!(decode(r"not\qan\escape"), None);
        assert_eq!(decode(r"truncated\u20"), None);
        assert_eq!(decode(r"trailing\"), None);
        // A lone surrogate has no character to decode to.
        assert_eq!(decode(r"surrogate\ud800"), None);
        // A hex escape that is not valid UTF-8 on its own — restic writes these
        // for filenames that are not UTF-8, and they cannot become a `String`.
        assert_eq!(decode(r"invalid\xff"), None);
        // A hex-escape run that *is* valid UTF-8 decodes.
        assert_eq!(decode(r"valid\xc3\xa9").unwrap(), "valid\u{e9}");
    }

    #[test]
    fn names_without_escapes_are_untouched() {
        for name in ["plain.txt", "with space.txt", "\u{65e5}\u{672c}\u{8a9e}", ""] {
            assert_eq!(decode(name).unwrap(), name);
            assert_eq!(from_repo(name), name);
            assert_eq!(to_repo(name), name);
        }
    }

    #[test]
    fn printability_matches_go() {
        // Printable: Go quotes none of these.
        for c in [' ', 'a', '\u{e9}', '\u{5f71}', '\u{1f600}'] {
            assert!(is_printable(c), "{c:?} should be printable");
        }
        // Not printable: every separator but the ASCII space, and the controls.
        for c in ['\u{2002}', '\u{a0}', '\u{3000}', '\n', '\u{7f}', '\0'] {
            assert!(!is_printable(c), "{c:?} should not be printable");
        }
    }
}
