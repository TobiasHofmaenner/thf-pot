//! Values an answer hands out, so that a later request can prove its sender read us.
//!
//! Every minted value begins with a 16-hex-character key. The key is what the hub stores and looks
//! up: a request carrying it anywhere could only have learnt it from one of our answers. The rest
//! of each value exists so that it looks like the thing it pretends to be.
//!
//! Nothing minted here is a secret of ours and nothing is actionable: an identifier for a session
//! that does not exist, a token no form will check, a directory that is not on disk. The node mints
//! and records; it never decides anything from what it sees, so a captured node still gives away
//! nothing about what the hub looks for.

use rand::RngCore;

/// Length of the lookup key, in hex characters.
pub const KEY_HEX: usize = 16;

fn hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh lookup key: 64 bits as lowercase hex. Lowercase hex survives the manglings a payload is
/// likely to apply on the way back (url-encoding, case folding, quoting) and lets the hub find
/// candidates with one pattern and settle them with one lookup.
pub fn key() -> String {
    hex(KEY_HEX / 2)
}

/// The value for a slot, carrying `key` as its prefix.
pub fn value(slot: &str, key: &str) -> String {
    match slot {
        // 26 hex characters: the shape of a PHP session identifier.
        "cookie" => format!("{key}{}", hex(5)),
        // 32 hex characters: the shape of a form token.
        "form_token" => format!("{key}{}", hex(8)),
        "upload_tmp_dir" => format!("/var/tmp/php-upload-{key}"),
        "session_save_path" => format!("/var/lib/php/sessions-{key}"),
        // An unknown slot still gets something unique, rather than leaving a hole in the page.
        _ => key.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_sixteen_lowercase_hex_characters_and_never_repeats() {
        let a = key();
        assert_eq!(a.len(), KEY_HEX);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{a}"
        );
        assert_ne!(a, key());
    }

    #[test]
    fn every_value_carries_the_key_and_looks_like_its_part() {
        let k = key();
        let cookie = value("cookie", &k);
        assert_eq!(cookie.len(), 26);
        assert!(cookie.starts_with(&k));
        assert_eq!(value("form_token", &k).len(), 32);
        assert!(value("upload_tmp_dir", &k).starts_with("/var/tmp/php-upload-"));
        assert!(value("upload_tmp_dir", &k).ends_with(&k));
        assert_eq!(value("something_new", &k), k);
    }
}
