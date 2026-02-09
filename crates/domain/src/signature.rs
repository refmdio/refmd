//! Signature Protocol Module
//!
//! Defines the signature protocol format for all cryptographic signatures.
//! Per spec: All signatures use canonicalized JSON with protocol, version, and action fields.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Signature protocol constants
pub const SIGNATURE_PROTOCOL: &str = "doclock-v1";
pub const SIGNATURE_VERSION: u32 = 1;

/// Signature action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAction {
    /// Trust state transfer signature
    TrustStateTransfer,
    /// Proof of Possession challenge signature
    PopChallenge,
    /// Device approval signature
    DeviceApproval,
    /// Device registration (identity key signs device keys at registration)
    DeviceRegistration,
    /// Device revocation (identity key signs revocation event)
    DeviceRevocation,
    /// Document update (device signing key signs update metadata)
    DocumentUpdate,
}

impl SignatureAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAction::TrustStateTransfer => "transfer_trust_state",
            SignatureAction::PopChallenge => "pop_challenge",
            SignatureAction::DeviceApproval => "device_approval",
            SignatureAction::DeviceRegistration => "device_registration",
            SignatureAction::DeviceRevocation => "device_revocation",
            SignatureAction::DocumentUpdate => "document_update",
        }
    }
}

/// Validate a JSON number for JCS compliance:
/// - Must be finite (no NaN, Infinity)
/// - Must be safe integer (no floating point, within 53-bit signed range)
/// - Must serialize as integer (not "1.0" but "1") for FE/BE consistency
///
/// # Panics
/// Panics if the number is not JCS compliant
fn validate_jcs_number(n: &serde_json::Number) {
    const MAX_SAFE_INTEGER: i64 = 9007199254740991; // 2^53 - 1
    const MIN_SAFE_INTEGER: i64 = -9007199254740991; // -(2^53 - 1)

    if let Some(i) = n.as_i64() {
        // Check if i64 is within safe integer range
        if i > MAX_SAFE_INTEGER || i < MIN_SAFE_INTEGER {
            panic!("JCS error: number {} outside safe integer range (53-bit)", i);
        }
    } else if let Some(u) = n.as_u64() {
        // Check if u64 exceeds safe integer range (2^53 - 1)
        if u > MAX_SAFE_INTEGER as u64 {
            panic!("JCS error: number {} outside safe integer range (53-bit)", u);
        }
    } else {
        // If it's not representable as i64 or u64, it's a float.
        // Reject ALL floats to ensure FE/BE serialization consistency.
        // (e.g., Rust serializes 1.0 as "1.0" but JS serializes as "1")
        panic!(
            "JCS error: floating point numbers not allowed (use integer types). Value: {}",
            n
        );
    }
}

/// Recursively sort object keys and validate values for RFC 8785 JCS compliance.
/// - Arrays maintain order, objects have keys sorted by Unicode code point
/// - Numbers are validated for JCS compliance (safe integers only)
///
/// # Panics
/// Panics if the value contains JCS-invalid data
/// Public alias for sort_value for use in update_hash computation
pub fn sort_value_public(value: Value) -> Value {
    sort_value(value)
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // BTreeMap sorts by Rust's Ord for String, which is lexicographic
            // byte order (UTF-8), matching Unicode code point order for valid UTF-8
            let sorted: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_value(v)))
                .collect();
            Value::Object(serde_json::Map::from_iter(sorted))
        }
        Value::Array(arr) => {
            Value::Array(arr.into_iter().map(sort_value).collect())
        }
        Value::Number(n) => {
            validate_jcs_number(&n);
            Value::Number(n)
        }
        other => other,
    }
}

/// Build a signature message using the signature protocol format.
///
/// The message is a canonicalized JSON object (sorted keys, no whitespace)
/// containing protocol, version, action, and any additional payload fields.
///
/// # Arguments
/// * `action` - The signature action type
/// * `payload` - Additional fields to include in the message
///
/// # Returns
/// Canonicalized JSON bytes ready for signing
///
/// # Panics
/// Panics if payload serialization fails (JCS compliance guard)
pub fn build_signature_message<T: Serialize>(action: SignatureAction, payload: &T) -> Vec<u8> {
    // Serialize payload to JSON Value - panic on failure for JCS compliance
    let payload_value = serde_json::to_value(payload)
        .expect("JCS error: payload serialization failed");

    // Build base message with protocol fields
    let mut message: BTreeMap<String, Value> = BTreeMap::new();
    message.insert("protocol".to_string(), Value::String(SIGNATURE_PROTOCOL.to_string()));
    message.insert("version".to_string(), Value::Number(SIGNATURE_VERSION.into()));
    message.insert("action".to_string(), Value::String(action.as_str().to_string()));

    // Merge payload fields with recursive sorting (BTreeMap ensures sorted keys)
    if let Value::Object(obj) = payload_value {
        for (key, value) in obj {
            message.insert(key, sort_value(value));
        }
    }

    // Serialize to canonical JSON - panic on failure for JCS compliance
    serde_json::to_vec(&message)
        .expect("JCS error: message serialization failed")
}

/// Build a PoP challenge signature message.
///
/// # Arguments
/// * `challenge` - Base64url-encoded challenge string
/// * `device_id` - Device UUID string
///
/// # Returns
/// Canonicalized JSON bytes ready for signing
pub fn build_pop_signature_message(challenge: &str, device_id: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct PopPayload<'a> {
        challenge: &'a str,
        device_id: &'a str,
    }

    build_signature_message(
        SignatureAction::PopChallenge,
        &PopPayload { challenge, device_id },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_pop_signature_message() {
        let message = build_pop_signature_message("test-challenge", "device-123");
        let json: Value = serde_json::from_slice(&message).unwrap();

        assert_eq!(json["protocol"], "doclock-v1");
        assert_eq!(json["version"], 1);
        assert_eq!(json["action"], "pop_challenge");
        assert_eq!(json["challenge"], "test-challenge");
        assert_eq!(json["device_id"], "device-123");
    }

    #[test]
    fn test_message_is_canonicalized() {
        let message = build_pop_signature_message("a", "b");
        let json_str = String::from_utf8_lossy(&message);

        // Keys should be sorted alphabetically
        let expected_prefix = r#"{"action":"pop_challenge","challenge":"a","device_id":"b"#;
        assert!(json_str.starts_with(expected_prefix));
    }

    #[test]
    fn test_nested_object_keys_sorted() {
        // Test that nested objects have their keys sorted recursively (RFC 8785 JCS compliance)
        #[derive(Serialize)]
        struct NestedPayload {
            z_field: String,
            a_field: String,
            nested: NestedInner,
        }

        #[derive(Serialize)]
        struct NestedInner {
            z_inner: String,
            a_inner: String,
        }

        let payload = NestedPayload {
            z_field: "z".to_string(),
            a_field: "a".to_string(),
            nested: NestedInner {
                z_inner: "z".to_string(),
                a_inner: "a".to_string(),
            },
        };

        let message = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
        let json_str = String::from_utf8_lossy(&message);

        // Verify top-level keys are sorted: a_field before nested before z_field
        assert!(json_str.contains(r#""a_field":"a","action":"transfer_trust_state""#));
        // Verify nested keys are sorted: a_inner before z_inner
        assert!(json_str.contains(r#""nested":{"a_inner":"a","z_inner":"z"}"#));
    }

    #[test]
    fn test_array_in_nested_object() {
        // Test that arrays within nested objects are handled correctly
        #[derive(Serialize)]
        struct ArrayPayload {
            items: Vec<Item>,
        }

        #[derive(Serialize)]
        struct Item {
            z_key: String,
            a_key: String,
        }

        let payload = ArrayPayload {
            items: vec![
                Item { z_key: "z1".to_string(), a_key: "a1".to_string() },
                Item { z_key: "z2".to_string(), a_key: "a2".to_string() },
            ],
        };

        let message = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
        let json_str = String::from_utf8_lossy(&message);

        // Array order should be preserved, but object keys within array elements should be sorted
        assert!(json_str.contains(r#"[{"a_key":"a1","z_key":"z1"},{"a_key":"a2","z_key":"z2"}]"#));
    }

    #[test]
    fn test_jcs_valid_integers() {
        // Test that valid integers are accepted
        #[derive(Serialize)]
        struct IntPayload {
            small: i64,
            zero: i64,
            negative: i64,
            max_safe: i64,
        }

        let payload = IntPayload {
            small: 42,
            zero: 0,
            negative: -100,
            max_safe: 9007199254740991, // 2^53 - 1
        };

        // Should not panic
        let message = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
        let json_str = String::from_utf8_lossy(&message);
        assert!(json_str.contains(r#""small":42"#));
    }

    #[test]
    #[should_panic(expected = "JCS error: floating point numbers not allowed (use integer types)")]
    fn test_jcs_rejects_floats() {
        #[derive(Serialize)]
        struct FloatPayload {
            value: f64,
        }

        let payload = FloatPayload { value: 3.14 };
        let _ = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
    }

    #[test]
    #[should_panic(expected = "JCS error: number")]
    fn test_jcs_rejects_large_integers() {
        #[derive(Serialize)]
        struct LargePayload {
            value: u64,
        }

        let payload = LargePayload {
            value: 9007199254740992, // 2^53, exceeds safe integer
        };
        let _ = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
    }

    #[test]
    #[should_panic(expected = "JCS error: floating point numbers not allowed (use integer types)")]
    fn test_jcs_rejects_integer_like_floats() {
        // Even 1.0 must be rejected because Rust serializes it as "1.0"
        // but JS would serialize it as "1", causing signature mismatch
        #[derive(Serialize)]
        struct FloatPayload {
            value: f64,
        }

        let payload = FloatPayload { value: 1.0 };
        let _ = build_signature_message(SignatureAction::TrustStateTransfer, &payload);
    }

    // ===================================================================
    // Cross-platform test vectors
    //
    // These tests use fixed inputs and verify exact byte output.
    // The TypeScript implementation MUST produce identical results.
    // ===================================================================

    #[test]
    fn test_cross_platform_device_registration_vector() {
        #[derive(Serialize)]
        struct RegistrationPayload {
            client_nonce: String,
            device_ecdh_public_key: String,
            device_signing_public_key: String,
        }

        let message = build_signature_message(
            SignatureAction::DeviceRegistration,
            &RegistrationPayload {
                device_signing_public_key: "dHNwaw".to_string(), // base64url("tspk")
                device_ecdh_public_key: "ZGVwaw".to_string(),    // base64url("depk")
                client_nonce: "bm9uY2U".to_string(),              // base64url("nonce")
            },
        );

        let json_str = String::from_utf8(message).unwrap();
        // Keys are sorted alphabetically: action, client_nonce, device_ecdh_public_key,
        // device_signing_public_key, protocol, version
        assert_eq!(
            json_str,
            r#"{"action":"device_registration","client_nonce":"bm9uY2U","device_ecdh_public_key":"ZGVwaw","device_signing_public_key":"dHNwaw","protocol":"doclock-v1","version":1}"#
        );
    }

    #[test]
    fn test_cross_platform_device_revocation_vector() {
        #[derive(Serialize)]
        struct RevocationPayload {
            device_id: String,
            reason: String,
            revoked_at: i64,
        }

        let message = build_signature_message(
            SignatureAction::DeviceRevocation,
            &RevocationPayload {
                device_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                reason: "compromised".to_string(),
                revoked_at: 1700000000000i64,
            },
        );

        let json_str = String::from_utf8(message).unwrap();
        // Keys sorted: action, device_id, protocol, reason, revoked_at, version
        assert_eq!(
            json_str,
            r#"{"action":"device_revocation","device_id":"550e8400-e29b-41d4-a716-446655440000","protocol":"doclock-v1","reason":"compromised","revoked_at":1700000000000,"version":1}"#
        );
    }

    #[test]
    fn test_cross_platform_document_update_vector() {
        // Test with prev_update_hash = null (first update in chain)
        #[derive(Serialize)]
        struct DocumentUpdatePayload {
            document_id: String,
            key_version: i64,
            prev_update_hash: Option<String>,
            timestamp: i64,
            update_hash: String,
        }

        let message = build_signature_message(
            SignatureAction::DocumentUpdate,
            &DocumentUpdatePayload {
                document_id: "660e8400-e29b-41d4-a716-446655440001".to_string(),
                key_version: 1,
                prev_update_hash: None, // null in JSON
                timestamp: 1700000000000i64,
                update_hash: "dXBkYXRlX2hhc2g".to_string(), // base64url("update_hash")
            },
        );

        let json_str = String::from_utf8(message).unwrap();
        // Keys sorted: action, document_id, key_version, prev_update_hash, protocol, timestamp, update_hash, version
        // prev_update_hash serializes as null (not omitted)
        assert_eq!(
            json_str,
            r#"{"action":"document_update","document_id":"660e8400-e29b-41d4-a716-446655440001","key_version":1,"prev_update_hash":null,"protocol":"doclock-v1","timestamp":1700000000000,"update_hash":"dXBkYXRlX2hhc2g","version":1}"#
        );

        // Test with prev_update_hash = Some (subsequent update)
        let message2 = build_signature_message(
            SignatureAction::DocumentUpdate,
            &DocumentUpdatePayload {
                document_id: "660e8400-e29b-41d4-a716-446655440001".to_string(),
                key_version: 1,
                prev_update_hash: Some("cHJldl9oYXNo".to_string()), // base64url("prev_hash")
                timestamp: 1700000001000i64,
                update_hash: "bmV3X2hhc2g".to_string(), // base64url("new_hash")
            },
        );

        let json_str2 = String::from_utf8(message2).unwrap();
        assert_eq!(
            json_str2,
            r#"{"action":"document_update","document_id":"660e8400-e29b-41d4-a716-446655440001","key_version":1,"prev_update_hash":"cHJldl9oYXNo","protocol":"doclock-v1","timestamp":1700000001000,"update_hash":"bmV3X2hhc2g","version":1}"#
        );
    }
}
