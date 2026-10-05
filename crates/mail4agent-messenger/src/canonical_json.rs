//! Matrix canonical JSON (spec "Canonical JSON":
//! <https://spec.matrix.org/latest/appendices/#canonical-json>) plus
//! [`sign_json`]/[`verify_json_signature`], the two operations every signed
//! Matrix object (`device_keys`, one-time/fallback keys, room events, ...)
//! is built from.
//!
//! # The canonicalization rules
//!
//! - Object keys are sorted by Unicode code point. Rust's `str`/`String`
//!   `Ord` already compares by UTF-8 byte value, which is equivalent to
//!   code-point order for well-formed UTF-8 — no separate collation step is
//!   needed.
//! - No insignificant whitespace: no space after `:` or `,`, no trailing
//!   newline.
//! - Strings use standard JSON escaping (quote, backslash, and the C0
//!   control characters) and are otherwise emitted as raw UTF-8 — non-ASCII
//!   characters are **not** `\uXXXX`-escaped, matching both the spec and
//!   `serde_json`'s own default (non-`ascii`-feature) behaviour.
//! - Numbers must be integers in the inclusive range
//!   `-(2^53-1)..=2^53-1` (JavaScript's safe-integer range — the reason the
//!   spec picks it at all). Floating-point values are forbidden outright,
//!   not merely range-checked.
//!
//! # Signing
//!
//! [`sign_json`] and [`verify_json_signature`] implement the spec's
//! "Signing JSON" algorithm: strip `signatures` and `unsigned`, canonicalize
//! what's left, sign/verify those exact bytes, then (for signing) restore
//! `unsigned` and insert the new signature under `signatures.{user_id}.{key_id}`.

use mail4agent_vodozemac::{Ed25519PublicKey, Ed25519Signature, SignatureError};
use serde_json::{Map, Value};

/// The inclusive safe-integer bound canonical JSON permits, in both
/// directions (`-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER`). `2^53 - 1`.
const MAX_SAFE_INTEGER: i128 = 9_007_199_254_740_991;

/// Every way canonicalizing or (de)signing a JSON value can fail.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalJsonError {
    /// [`sign_json`]/[`verify_json_signature`] require a JSON object (there
    /// has to be somewhere to put `signatures`); [`to_canonical_json`]
    /// itself has no such restriction and accepts any [`Value`].
    #[error("expected a JSON object")]
    NotAnObject,

    /// Canonical JSON forbids floating-point numbers outright — not a range
    /// check, a type restriction.
    #[error("canonical JSON forbids floating-point numbers")]
    FloatNotAllowed,

    /// An integer fell outside the safe range `-(2^53-1)..=2^53-1` canonical
    /// JSON requires (this is JavaScript's safe-integer range).
    #[error("integer {0} is outside the safe range -(2^53-1)..=2^53-1")]
    IntegerOutOfRange(i128),

    /// [`verify_json_signature`] found no signature for the requested
    /// `(user_id, key_id)` pair at all — distinct from a signature that was
    /// present but did not verify ([`CanonicalJsonError::Signature`]).
    #[error("no signature found for user {user_id:?} key {key_id:?}")]
    MissingSignature {
        /// The user id the caller asked to verify a signature for.
        user_id: String,
        /// The key id the caller asked to verify a signature for.
        key_id: String,
    },

    /// A signature was present but failed to decode or failed cryptographic
    /// verification.
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

/// Canonicalizes `value` into the exact byte sequence the Matrix spec's
/// canonical-JSON algorithm defines — see the module doc for the rules.
/// Accepts any [`Value`], not only objects (canonical JSON is defined
/// recursively over every JSON type).
pub fn to_canonical_json(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (key, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalJsonError> {
    let as_i128: i128 = match (n.as_i64(), n.as_u64()) {
        (Some(i), _) => i128::from(i),
        (None, Some(u)) => i128::from(u),
        // Neither representation is exact: this is a floating-point number.
        (None, None) => return Err(CanonicalJsonError::FloatNotAllowed),
    };
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&as_i128) {
        return Err(CanonicalJsonError::IntegerOutOfRange(as_i128));
    }
    out.push_str(&n.to_string());
    Ok(())
}

/// Writes `s` as a quoted, standard-escaped JSON string: `"`, `\`, and the C0
/// control characters are escaped; every other character (including
/// non-ASCII UTF-8) is emitted raw.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Signs `value` in place following the spec's "Signing JSON" algorithm:
/// `signatures` and `unsigned` are removed, what remains is canonicalized
/// and passed to `sign`, then `unsigned` is restored and the new signature
/// (`sign`'s return value, already the raw `Ed25519Signature`) is inserted
/// as base64 under `signatures.{user_id}.{key_id}` — merged into whatever
/// `signatures` object was already present, so signing under one key id
/// never clobbers a signature already recorded under a different one.
///
/// `value` must be a JSON object, or this returns
/// [`CanonicalJsonError::NotAnObject`] and leaves `value` untouched.
pub fn sign_json<F>(
    value: &mut Value,
    user_id: &str,
    key_id: &str,
    sign: F,
) -> Result<(), CanonicalJsonError>
where
    F: FnOnce(&[u8]) -> Ed25519Signature,
{
    let existing_signatures = value.as_object_mut().ok_or(CanonicalJsonError::NotAnObject)?.remove("signatures");
    let existing_unsigned = value.as_object_mut().ok_or(CanonicalJsonError::NotAnObject)?.remove("unsigned");

    let canonical = to_canonical_json(value)?;
    let signature = sign(canonical.as_bytes());

    let obj = value.as_object_mut().ok_or(CanonicalJsonError::NotAnObject)?;
    let mut signatures_map = match existing_signatures {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let user_signatures =
        signatures_map.entry(user_id.to_string()).or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(by_key) = user_signatures {
        by_key.insert(key_id.to_string(), Value::String(signature.to_base64()));
    }
    obj.insert("signatures".to_string(), Value::Object(signatures_map));
    if let Some(unsigned) = existing_unsigned {
        obj.insert("unsigned".to_string(), unsigned);
    }
    Ok(())
}

/// Verifies that `value` carries a valid signature from `public_key` under
/// `signatures.{user_id}.{key_id}`, following the same "strip, canonicalize,
/// check" algorithm [`sign_json`] uses to produce one.
///
/// `value` is not mutated — verification canonicalizes a clone with
/// `signatures`/`unsigned` stripped.
pub fn verify_json_signature(
    value: &Value,
    user_id: &str,
    key_id: &str,
    public_key: &Ed25519PublicKey,
) -> Result<(), CanonicalJsonError> {
    let obj = value.as_object().ok_or(CanonicalJsonError::NotAnObject)?;
    let signature_b64 = obj
        .get("signatures")
        .and_then(Value::as_object)
        .and_then(|by_user| by_user.get(user_id))
        .and_then(Value::as_object)
        .and_then(|by_key| by_key.get(key_id))
        .and_then(Value::as_str)
        .ok_or_else(|| CanonicalJsonError::MissingSignature {
            user_id: user_id.to_string(),
            key_id: key_id.to_string(),
        })?;
    let signature = Ed25519Signature::from_base64(signature_b64)?;

    let mut stripped = value.clone();
    if let Some(stripped_obj) = stripped.as_object_mut() {
        stripped_obj.remove("signatures");
        stripped_obj.remove("unsigned");
    }
    let canonical = to_canonical_json(&stripped)?;

    public_key.verify(canonical.as_bytes(), &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Canonical-JSON shape: examples from the Matrix spec's
    // "Canonical JSON" appendix (<https://spec.matrix.org/latest/appendices/#canonical-json>). ----

    #[test]
    fn canonical_json_examples_from_the_matrix_spec() {
        assert_eq!(to_canonical_json(&serde_json::json!({})).expect("empty object"), "{}");

        assert_eq!(
            to_canonical_json(&serde_json::json!({"one": 1, "two": "Two"}))
                .expect("already-sorted keys canonicalize unchanged"),
            r#"{"one":1,"two":"Two"}"#
        );

        assert_eq!(
            to_canonical_json(&serde_json::json!({"b": "2", "a": "1"}))
                .expect("out-of-order keys are sorted"),
            r#"{"a":"1","b":"2"}"#
        );

        assert_eq!(
            to_canonical_json(&serde_json::json!({"b": "2", "a": "1", "c": {"y": 1, "x": 2}}))
                .expect("nested objects are sorted independently"),
            r#"{"a":"1","b":"2","c":{"x":2,"y":1}}"#
        );

        assert_eq!(
            to_canonical_json(&serde_json::json!({"a": null})).expect("null values are kept"),
            r#"{"a":null}"#
        );
    }

    #[test]
    fn canonical_json_matches_the_spec_nested_auth_example() {
        let value = serde_json::json!({
            "auth": {
                "success": true,
                "mxid": "@john.doe:example.com",
                "profile": {
                    "display_name": "John Doe",
                    "three_pids": [
                        { "medium": "email", "address": "john.doe@example.org" },
                        { "medium": "msisdn", "address": "123456789" }
                    ]
                }
            }
        });
        assert_eq!(
            to_canonical_json(&value).expect("the spec's own nested example canonicalizes"),
            concat!(
                "{\"auth\":{\"mxid\":\"@john.doe:example.com\",",
                "\"profile\":{\"display_name\":\"John Doe\",",
                "\"three_pids\":[{\"address\":\"john.doe@example.org\",\"medium\":\"email\"},",
                "{\"address\":\"123456789\",\"medium\":\"msisdn\"}]},",
                "\"success\":true}}"
            )
        );
    }

    #[test]
    fn canonical_json_keeps_non_ascii_as_raw_utf8_not_escaped() {
        let value = serde_json::json!({"a": "日本"});
        assert_eq!(
            to_canonical_json(&value).expect("unicode canonicalizes"),
            "{\"a\":\"日本\"}"
        );
    }

    #[test]
    fn canonical_json_escapes_quote_and_backslash_and_control_characters() {
        let value = serde_json::json!({"a": "\"\\\n\t\u{01}"});
        assert_eq!(
            to_canonical_json(&value).expect("escaped string canonicalizes"),
            "{\"a\":\"\\\"\\\\\\n\\t\\u0001\"}"
        );
    }

    #[test]
    fn canonical_json_rejects_floating_point_numbers() {
        let value = serde_json::json!({"a": 1.5});
        assert!(matches!(to_canonical_json(&value), Err(CanonicalJsonError::FloatNotAllowed)));
    }

    #[test]
    fn canonical_json_accepts_the_largest_and_smallest_safe_integers() {
        let value = serde_json::json!({
            "max": 9_007_199_254_740_991i64,
            "min": -9_007_199_254_740_991i64,
        });
        assert_eq!(
            to_canonical_json(&value).expect("safe-range integers canonicalize"),
            r#"{"max":9007199254740991,"min":-9007199254740991}"#
        );
    }

    #[test]
    fn canonical_json_rejects_integers_outside_the_safe_range() {
        let too_big = serde_json::json!({"n": 9_007_199_254_740_992i64});
        assert!(matches!(to_canonical_json(&too_big), Err(CanonicalJsonError::IntegerOutOfRange(_))));

        let too_small = serde_json::json!({"n": -9_007_199_254_740_992i64});
        assert!(matches!(to_canonical_json(&too_small), Err(CanonicalJsonError::IntegerOutOfRange(_))));
    }

    #[test]
    fn to_canonical_json_accepts_non_object_top_level_values() {
        // Canonical JSON is defined over every JSON type -- only the signing
        // helpers below require an object (somewhere to put `signatures`).
        assert_eq!(to_canonical_json(&serde_json::json!([3, 1, 2])).expect("array"), "[3,1,2]");
        assert_eq!(to_canonical_json(&serde_json::json!("hi")).expect("string"), "\"hi\"");
    }

    // ---- Signing / verification. ----

    #[test]
    fn sign_json_strips_signatures_and_unsigned_before_signing_and_round_trips() {
        let account = mail4agent_vodozemac::olm::Account::new();
        let public = account.identity_keys().ed25519;

        let mut value = serde_json::json!({
            "hello": "world",
            "unsigned": {"age": 1234},
        });
        sign_json(&mut value, "@alice:example.org", "ed25519:DEV1", |bytes| account.sign(bytes))
            .expect("signing a fresh object succeeds");

        assert_eq!(value["unsigned"], serde_json::json!({"age": 1234}), "unsigned is restored");
        assert!(value["signatures"]["@alice:example.org"]["ed25519:DEV1"].is_string());

        verify_json_signature(&value, "@alice:example.org", "ed25519:DEV1", &public)
            .expect("freshly produced signature must verify");
    }

    #[test]
    fn sign_json_merges_into_an_existing_signatures_object() {
        let account = mail4agent_vodozemac::olm::Account::new();
        let mut value = serde_json::json!({
            "hello": "world",
            "signatures": {"@bob:example.org": {"ed25519:OTHER": "not-a-real-signature"}},
        });
        sign_json(&mut value, "@alice:example.org", "ed25519:DEV1", |bytes| account.sign(bytes))
            .expect("signing succeeds");

        assert_eq!(value["signatures"]["@bob:example.org"]["ed25519:OTHER"], "not-a-real-signature");
        assert!(value["signatures"]["@alice:example.org"]["ed25519:DEV1"].is_string());
    }

    #[test]
    fn sign_json_rejects_a_non_object_value() {
        let account = mail4agent_vodozemac::olm::Account::new();
        let mut value = serde_json::json!([1, 2, 3]);
        let err = sign_json(&mut value, "@a:x", "ed25519:D", |bytes| account.sign(bytes))
            .expect_err("an array cannot carry signatures");
        assert!(matches!(err, CanonicalJsonError::NotAnObject));
    }

    #[test]
    fn verify_json_signature_rejects_a_missing_signature() {
        let account = mail4agent_vodozemac::olm::Account::new();
        let value = serde_json::json!({"hello": "world"});
        let err = verify_json_signature(
            &value,
            "@alice:example.org",
            "ed25519:DEV1",
            &account.identity_keys().ed25519,
        )
        .expect_err("no signatures object at all must be rejected");
        assert!(matches!(err, CanonicalJsonError::MissingSignature { .. }));
    }

    #[test]
    fn verify_json_signature_rejects_a_one_byte_mutation_after_signing() {
        let account = mail4agent_vodozemac::olm::Account::new();
        let mut value = serde_json::json!({"hello": "world"});
        sign_json(&mut value, "@alice:example.org", "ed25519:DEV1", |bytes| account.sign(bytes))
            .expect("sign");

        value["hello"] = Value::String("WORLD".to_string());

        let err = verify_json_signature(
            &value,
            "@alice:example.org",
            "ed25519:DEV1",
            &account.identity_keys().ed25519,
        )
        .expect_err("a mutated payload must fail verification");
        assert!(matches!(err, CanonicalJsonError::Signature(_)));
    }

    // ---- Independent vector: a real captured device, not generated by any
    // harness in this codebase. Lifted from matrix-rust-sdk,
    // `crates/matrix-sdk-crypto/src/olm/account.rs`,
    // `test_fallback_key_signature_verification` (lines ~2124-2164), commit
    // `9c9a786`, Apache-2.0 (`Copyright 2020 The Matrix.org Foundation
    // C.I.C.`). Device `EXPDYDPWZH` of `@dkasak_c:matrix.org`. ----

    const DKASAK_USER_ID: &str = "@dkasak_c:matrix.org";
    const DKASAK_DEVICE_KEY_ID: &str = "ed25519:EXPDYDPWZH";
    const DKASAK_DEVICE_ED25519: &str = "GdjYI8fxs175gSpYRJkyN6FRfvcyTsNOhJ2OR/Ggp+E";

    fn dkasak_device_ed25519() -> Ed25519PublicKey {
        Ed25519PublicKey::from_base64(DKASAK_DEVICE_ED25519).expect("fixture key decodes")
    }

    #[test]
    fn dkasak_device_keys_signature_verifies_against_a_real_captured_device() {
        let device_keys: Value = serde_json::from_str(
            r#"{
                "algorithms": [
                    "m.olm.v1.curve25519-aes-sha2",
                    "m.megolm.v1.aes-sha2"
                ],
                "device_id": "EXPDYDPWZH",
                "keys": {
                    "curve25519:EXPDYDPWZH": "k7f3igo0Vrdm88JSSA5d3OCuUfHYELChB2b57aOROB8",
                    "ed25519:EXPDYDPWZH": "GdjYI8fxs175gSpYRJkyN6FRfvcyTsNOhJ2OR/Ggp+E"
                },
                "signatures": {
                    "@dkasak_c:matrix.org": {
                        "ed25519:EXPDYDPWZH": "kzrtfQMbJXWXQ1uzhybtwFnGk0JJBS4Mg8VPMusMu6U8MPJccwoHVZKo5+owuHTzIodI+GZYqLmMSzvfvsChAA"
                    }
                },
                "user_id": "@dkasak_c:matrix.org",
                "unsigned": {}
            }"#,
        )
        .expect("fixture is valid JSON");

        verify_json_signature(&device_keys, DKASAK_USER_ID, DKASAK_DEVICE_KEY_ID, &dkasak_device_ed25519())
            .expect("a real device's own signature over its own device_keys must verify");

        let mut mutated = device_keys.clone();
        mutated["keys"]["curve25519:EXPDYDPWZH"] =
            Value::String("k7f3igo0Vrdm88JSSA5d3OCuUfHYELChB2b57aOROB9".to_string());
        verify_json_signature(&mutated, DKASAK_USER_ID, DKASAK_DEVICE_KEY_ID, &dkasak_device_ed25519())
            .expect_err("a one-byte mutation of the signed payload must invalidate the signature");
    }

    #[test]
    fn dkasak_fallback_key_signature_verifies_against_the_same_device() {
        let fallback_key: Value = serde_json::from_str(
            r#"{
                "fallback": true,
                "key": "XPFqtLvBepBmW6jSAbBuJbhEpprBhQOX1IjUu+cnMF4",
                "signatures": {
                    "@dkasak_c:matrix.org": {
                        "ed25519:EXPDYDPWZH": "RJCBMJPL5hvjxgq8rmLmqkNOuPsaan7JeL1wsE+gW6R39G894lb2sBmzapHeKCn/KFjmkonPLkICApRDS+zyDw"
                    }
                }
            }"#,
        )
        .expect("fixture is valid JSON");

        verify_json_signature(&fallback_key, DKASAK_USER_ID, DKASAK_DEVICE_KEY_ID, &dkasak_device_ed25519())
            .expect("the same device's fallback-key signature must also verify");

        let mut mutated = fallback_key.clone();
        mutated["key"] = Value::String("XPFqtLvBepBmW6jSAbBuJbhEpprBhQOX1IjUu+cnMF5".to_string());
        verify_json_signature(&mutated, DKASAK_USER_ID, DKASAK_DEVICE_KEY_ID, &dkasak_device_ed25519())
            .expect_err("a one-byte mutation of the fallback key must invalidate the signature");
    }
}
