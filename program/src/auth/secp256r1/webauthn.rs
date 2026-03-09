#[allow(unused_imports)]
use crate::error::AuthError;
#[allow(unused_imports)]
use pinocchio::program_error::ProgramError;

// =============================================================================
// BASE64URL ENCODING/DECODING
// =============================================================================

/// Simple Base64URL encoder without padding
pub fn base64url_encode_no_pad(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = Vec::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | (chunk[2] as u32),
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            1 => (chunk[0] as u32) << 16,
            _ => unreachable!(),
        };

        result.push(ALPHABET[((b >> 18) & 0x3f) as usize]);
        result.push(ALPHABET[((b >> 12) & 0x3f) as usize]);
        if chunk.len() > 1 {
            result.push(ALPHABET[((b >> 6) & 0x3f) as usize]);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(b & 0x3f) as usize]);
        }
    }
    result
}

/// Base64URL decoder (handles no padding)
/// Returns None if invalid base64url
pub fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &c in input {
        // Skip padding if present
        if c == b'=' {
            continue;
        }
        let val = decode_char(c)?;
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(result)
}

// =============================================================================
// CLIENT DATA JSON PARSING
// =============================================================================

/// Extracts the "challenge" field value from clientDataJSON bytes.
/// 
/// WebAuthn clientDataJSON format (field order varies by browser!):
/// {"type":"webauthn.get","challenge":"BASE64URL","origin":"https://...","crossOrigin":false}
/// 
/// Chrome may add: "other_keys_can_be_added_here":"do not compare clientDataJSON against a template..."
/// Safari may omit crossOrigin entirely.
/// 
/// This parser handles any field order and ignores unknown fields.
pub fn extract_challenge_from_client_data_json(json: &[u8]) -> Option<Vec<u8>> {
    // Find "challenge":" pattern
    let pattern = b"\"challenge\":\"";
    let pos = find_subsequence(json, pattern)?;
    let start = pos + pattern.len();
    
    // Find closing quote
    let rest = &json[start..];
    let end_quote = rest.iter().position(|&c| c == b'"')?;
    
    // Extract and decode base64url challenge
    let challenge_b64 = &rest[..end_quote];
    base64url_decode(challenge_b64)
}

/// Extracts the "origin" field value from clientDataJSON bytes.
/// Returns the origin as raw bytes (e.g., "https://example.com")
pub fn extract_origin_from_client_data_json(json: &[u8]) -> Option<&[u8]> {
    let pattern = b"\"origin\":\"";
    let pos = find_subsequence(json, pattern)?;
    let start = pos + pattern.len();
    
    let rest = &json[start..];
    let end_quote = rest.iter().position(|&c| c == b'"')?;
    
    Some(&rest[..end_quote])
}

/// Extracts the "type" field value from clientDataJSON bytes.
/// Should be "webauthn.get" or "webauthn.create"
pub fn extract_type_from_client_data_json(json: &[u8]) -> Option<&[u8]> {
    let pattern = b"\"type\":\"";
    let pos = find_subsequence(json, pattern)?;
    let start = pos + pattern.len();
    
    let rest = &json[start..];
    let end_quote = rest.iter().position(|&c| c == b'"')?;
    
    Some(&rest[..end_quote])
}

/// Find subsequence in a slice
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Verifies clientDataJSON contains the expected challenge.
/// 
/// # Arguments
/// * `client_data_json` - The actual clientDataJSON bytes from WebAuthn assertion
/// * `expected_challenge` - The expected challenge bytes (NOT base64 encoded)
/// 
/// # Returns
/// * `Ok(())` if challenge matches
/// * `Err(AuthError::InvalidMessageHash)` if challenge doesn't match or parsing fails
pub fn verify_client_data_json_challenge(
    client_data_json: &[u8],
    expected_challenge: &[u8],
) -> Result<(), ProgramError> {
    // Extract challenge from JSON
    let challenge = extract_challenge_from_client_data_json(client_data_json)
        .ok_or(AuthError::InvalidMessageHash)?;
    
    // Compare with expected
    if challenge.as_slice() != expected_challenge {
        return Err(AuthError::InvalidMessageHash.into());
    }
    
    Ok(())
}

/// Verifies the type field is "webauthn.get" (for assertions)
pub fn verify_client_data_json_type_get(client_data_json: &[u8]) -> Result<(), ProgramError> {
    let auth_type = extract_type_from_client_data_json(client_data_json)
        .ok_or(AuthError::InvalidMessage)?;
    
    if auth_type != b"webauthn.get" {
        return Err(AuthError::InvalidMessage.into());
    }
    
    Ok(())
}

// =============================================================================
// LEGACY: RECONSTRUCTION (kept for backward compatibility)
// =============================================================================

/// Packed flags for clientDataJson reconstruction (LEGACY)
/// 
/// NOTE: This reconstruction approach is DEPRECATED and should not be used.
/// Different browsers produce different JSON structures, so reconstruction fails.
/// Use `verify_client_data_json_challenge()` instead to parse actual JSON.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ClientDataJsonReconstructionParams {
    pub type_and_flags: u8,
}

impl ClientDataJsonReconstructionParams {
    #[allow(dead_code)]
    const TYPE_CREATE: u8 = 0x00;
    const TYPE_GET: u8 = 0x10;
    const FLAG_CROSS_ORIGIN: u8 = 0x01;
    const FLAG_HTTP_ORIGIN: u8 = 0x02;
    const FLAG_GOOGLE_EXTRA: u8 = 0x04;

    pub fn auth_type(&self) -> AuthType {
        if (self.type_and_flags & 0xF0) == Self::TYPE_GET {
            AuthType::Get
        } else {
            AuthType::Create
        }
    }

    pub fn is_cross_origin(&self) -> bool {
        self.type_and_flags & Self::FLAG_CROSS_ORIGIN != 0
    }

    pub fn is_http(&self) -> bool {
        self.type_and_flags & Self::FLAG_HTTP_ORIGIN != 0
    }

    pub fn has_google_extra(&self) -> bool {
        self.type_and_flags & Self::FLAG_GOOGLE_EXTRA != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AuthType {
    Create,
    Get,
}

/// DEPRECATED: Reconstructs clientDataJson (fails across browsers!)
/// 
/// This function attempts to rebuild what it thinks the JSON should look like.
/// This is WRONG because:
/// - Chrome adds "other_keys_can_be_added_here" field
/// - Safari may omit "crossOrigin"
/// - Field ordering varies
/// - Future browsers may add more fields
/// 
/// Use `verify_client_data_json_challenge()` to parse actual JSON instead.
#[deprecated(note = "Use verify_client_data_json_challenge() instead - reconstruction fails across browsers")]
pub fn reconstruct_client_data_json(
    params: &ClientDataJsonReconstructionParams,
    rp_id: &[u8],
    challenge: &[u8],
) -> Vec<u8> {
    let challenge_b64url = base64url_encode_no_pad(challenge);
    let type_str: &[u8] = match params.auth_type() {
        AuthType::Create => b"webauthn.create",
        AuthType::Get => b"webauthn.get",
    };

    let prefix: &[u8] = if params.is_http() {
        b"http://"
    } else {
        b"https://"
    };
    let cross_origin: &[u8] = if params.is_cross_origin() {
        b"true"
    } else {
        b"false"
    };

    let mut json = Vec::with_capacity(256);
    json.extend_from_slice(b"{\"type\":\"");
    json.extend_from_slice(type_str);
    json.extend_from_slice(b"\",\"challenge\":\"");
    json.extend_from_slice(&challenge_b64url);
    json.extend_from_slice(b"\",\"origin\":\"");
    json.extend_from_slice(prefix);
    json.extend_from_slice(rp_id);
    json.extend_from_slice(b"\",\"crossOrigin\":");
    json.extend_from_slice(cross_origin);

    if params.has_google_extra() {
        json.extend_from_slice(b",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"");
    }

    json.extend_from_slice(b"}");
    json
}

// =============================================================================
// AUTHENTICATOR DATA PARSER
// =============================================================================

/// Parser for WebAuthn authenticator data
pub struct AuthDataParser<'a> {
    data: &'a [u8],
}

impl<'a> AuthDataParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn rp_id_hash(&self) -> &'a [u8] {
        &self.data[0..32]
    }

    pub fn is_user_present(&self) -> bool {
        self.data[32] & 0x01 != 0
    }

    pub fn is_user_verified(&self) -> bool {
        self.data[32] & 0x04 != 0
    }

    pub fn counter(&self) -> u32 {
        u32::from_be_bytes(self.data[33..37].try_into().unwrap())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode_no_pad(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_extract_challenge_chrome() {
        // Chrome-style JSON with extra field
        let json = br#"{"type":"webauthn.get","challenge":"dGVzdF9jaGFsbGVuZ2U","origin":"https://example.com","crossOrigin":false,"other_keys_can_be_added_here":"do not compare"}"#;
        let challenge = extract_challenge_from_client_data_json(json).unwrap();
        assert_eq!(challenge, b"test_challenge");
    }

    #[test]
    fn test_extract_challenge_safari() {
        // Safari-style JSON (no crossOrigin, different order possible)
        let json = br#"{"type":"webauthn.get","challenge":"dGVzdF9jaGFsbGVuZ2U","origin":"https://example.com"}"#;
        let challenge = extract_challenge_from_client_data_json(json).unwrap();
        assert_eq!(challenge, b"test_challenge");
    }

    #[test]
    fn test_verify_challenge_match() {
        let json = br#"{"type":"webauthn.get","challenge":"dGVzdF9jaGFsbGVuZ2U","origin":"https://example.com"}"#;
        assert!(verify_client_data_json_challenge(json, b"test_challenge").is_ok());
    }

    #[test]
    fn test_verify_challenge_mismatch() {
        let json = br#"{"type":"webauthn.get","challenge":"dGVzdF9jaGFsbGVuZ2U","origin":"https://example.com"}"#;
        assert!(verify_client_data_json_challenge(json, b"wrong_challenge").is_err());
    }

    #[test]
    fn test_extract_origin() {
        let json = br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}"#;
        let origin = extract_origin_from_client_data_json(json).unwrap();
        assert_eq!(origin, b"https://example.com");
    }

    #[test]
    fn test_extract_type() {
        let json = br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}"#;
        let auth_type = extract_type_from_client_data_json(json).unwrap();
        assert_eq!(auth_type, b"webauthn.get");
    }
}
