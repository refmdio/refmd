//! SAS (Short Authentication String) generation
//!
//! Generates a human-comparable authentication string for device verification.
//! Uses BLAKE3 hash of public keys and client nonce, converted to emojis.

use blake3::Hasher;

/// SAS emoji list (256 emojis for 8-bit encoding per emoji)
/// Using Signal-style emoji set for familiarity
const SAS_EMOJIS: &[&str] = &[
    // 0-31: Animals
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼",
    "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺",
    "🐗", "🐴", "🦄", "🐝", "🐛", "🦋", "🐌", "🐞",
    // 32-63: More animals
    "🐜", "🦟", "🦗", "🕷", "🦂", "🐢", "🐍", "🦎",
    "🦖", "🦕", "🐙", "🦑", "🦐", "🦞", "🦀", "🐡",
    "🐠", "🐟", "🐬", "🐳", "🐋", "🦈", "🐊", "🐅",
    "🐆", "🦓", "🦍", "🦧", "🐘", "🦛", "🦏", "🐪",
    // 64-95: Nature & Food
    "🌵", "🎄", "🌲", "🌳", "🌴", "🌱", "🌿", "🍀",
    "🎍", "🎋", "🍃", "🍂", "🍁", "🌾", "🌺", "🌻",
    "🌹", "🥀", "🌷", "🌼", "🍎", "🍐", "🍊", "🍋",
    "🍌", "🍉", "🍇", "🍓", "🍈", "🍒", "🍑", "🥭",
    // 96-127: Food & Objects
    "🍍", "🥥", "🥝", "🍅", "🥑", "🥦", "🥬", "🥒",
    "🌶", "🌽", "🥕", "🧄", "🧅", "🥔", "🍠", "🥐",
    "🥯", "🍞", "🥖", "🥨", "🧀", "🥚", "🍳", "🧈",
    "🥞", "🧇", "🥓", "🥩", "🍗", "🍖", "🌭", "🍔",
    // 128-159: More Food & Objects
    "🍟", "🍕", "🥪", "🥙", "🧆", "🌮", "🌯", "🥗",
    "🥘", "🥫", "🍝", "🍜", "🍲", "🍛", "🍣", "🍱",
    "🥟", "🦪", "🍤", "🍙", "🍚", "🍘", "🍥", "🥠",
    "🍢", "🍡", "🍧", "🍨", "🍦", "🥧", "🧁", "🍰",
    // 160-191: Desserts & Objects
    "🎂", "🍮", "🍭", "🍬", "🍫", "🍿", "🧂", "🥤",
    "🧋", "🧃", "🧊", "🍵", "🍶", "🍾", "🍷", "🍸",
    "🍹", "🍺", "🍻", "🥂", "🥃", "🥡", "🥢", "🧉",
    "⚽", "🏀", "🏈", "⚾", "🥎", "🎾", "🏐", "🏉",
    // 192-223: Sports & Activities
    "🥏", "🎱", "🪀", "🏓", "🏸", "🏒", "🏑", "🥍",
    "🏏", "🪃", "🥅", "⛳", "🪁", "🏹", "🎣", "🤿",
    "🥊", "🥋", "🎽", "🛹", "🛼", "🛷", "⛸", "🥌",
    "🎿", "⛷", "🏂", "🪂", "🏋", "🤼", "🤸", "🤺",
    // 224-255: Objects & Symbols
    "🎪", "🎭", "🎨", "🎬", "🎤", "🎧", "🎼", "🎹",
    "🥁", "🎷", "🎺", "🎸", "🪕", "🎻", "🎲", "♟",
    "🎯", "🎳", "🎮", "🎰", "🧩", "🔮", "🎱", "🪄",
    "🧿", "🎴", "🀄", "🎭", "🖼", "🎨", "🧵", "🧶",
];

/// Generate SAS from public keys and nonce
///
/// ADR-008 compliant: Uses BLAKE3 hash of:
/// - Identity signing public key
/// - Device signing public key
/// - Device ECDH public key
/// - Client nonce (16 bytes)
///
/// Returns 7 emojis representing the first 56 bits of the hash
pub fn generate_sas(
    identity_signing_pk: &[u8],
    device_signing_pk: &[u8],
    device_ecdh_pk: &[u8],
    client_nonce: &[u8],
) -> String {
    let mut hasher = Hasher::new();
    hasher.update(identity_signing_pk);
    hasher.update(device_signing_pk);
    hasher.update(device_ecdh_pk);
    hasher.update(client_nonce);

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // Convert first 7 bytes to 7 emojis (one byte per emoji)
    let mut emojis = Vec::with_capacity(7);
    for &byte in &bytes[..7] {
        emojis.push(SAS_EMOJIS[byte as usize]);
    }

    emojis.join("")
}

/// Generate SAS as a list of emoji indices (for API response)
pub fn generate_sas_indices(
    identity_signing_pk: &[u8],
    device_signing_pk: &[u8],
    device_ecdh_pk: &[u8],
    client_nonce: &[u8],
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(identity_signing_pk);
    hasher.update(device_signing_pk);
    hasher.update(device_ecdh_pk);
    hasher.update(client_nonce);

    let hash = hasher.finalize();
    hash.as_bytes()[..7].to_vec()
}

/// Get the emoji list for client-side rendering
pub fn get_emoji_list() -> Vec<&'static str> {
    SAS_EMOJIS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sas_deterministic() {
        let identity_pk = [1u8; 32];
        let device_signing_pk = [2u8; 32];
        let device_ecdh_pk = [3u8; 32];
        let nonce = [4u8; 16];

        let sas1 = generate_sas(&identity_pk, &device_signing_pk, &device_ecdh_pk, &nonce);
        let sas2 = generate_sas(&identity_pk, &device_signing_pk, &device_ecdh_pk, &nonce);

        assert_eq!(sas1, sas2);
        assert_eq!(sas1.chars().count(), 7);
    }

    #[test]
    fn test_generate_sas_changes_with_input() {
        let identity_pk = [1u8; 32];
        let device_signing_pk = [2u8; 32];
        let device_ecdh_pk = [3u8; 32];
        let nonce1 = [4u8; 16];
        let nonce2 = [5u8; 16];

        let sas1 = generate_sas(&identity_pk, &device_signing_pk, &device_ecdh_pk, &nonce1);
        let sas2 = generate_sas(&identity_pk, &device_signing_pk, &device_ecdh_pk, &nonce2);

        assert_ne!(sas1, sas2);
    }

    #[test]
    fn test_emoji_list_size() {
        assert_eq!(SAS_EMOJIS.len(), 256);
    }
}
