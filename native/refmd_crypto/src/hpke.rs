use hpke_rs::{
    hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    rustcrypto::HpkeRustCrypto,
    Context, Hpke, HpkePrivateKey, HpkePublicKey, Mode,
};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x_wing::{kem::Decapsulator, kem::KeyExport, DecapsulationKey};

pub const PRIVATE_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 1216;
pub const ENCAPSULATED_KEY_BYTES: usize = 1120;
pub const X25519_PRIVATE_KEY_BYTES: usize = 32;

pub struct KeyMaterial {
    pub private_key: Vec<u8>,
    pub x25519_private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[cfg(test)]
pub struct SealedMessage {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct SenderSetup {
    pub encapsulated_key: Vec<u8>,
    pub context: Context<HpkeRustCrypto>,
}

pub fn generate_key_material() -> Result<KeyMaterial, &'static str> {
    let mut hpke = suite();
    let key_pair = hpke
        .generate_key_pair()
        .map_err(|_| "hpke_key_generation_failed")?;
    let (private_key, public_key) = key_pair.into_keys();
    key_material(private_key.as_slice(), public_key.as_slice())
}

pub fn derive_key_material(private_key: &[u8]) -> Result<KeyMaterial, &'static str> {
    validate_length(private_key, PRIVATE_KEY_BYTES, "hpke_private_key_invalid")?;
    let private_key_array: [u8; PRIVATE_KEY_BYTES] = private_key
        .try_into()
        .map_err(|_| "hpke_private_key_invalid")?;
    let decapsulation_key = DecapsulationKey::from(private_key_array);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    key_material(private_key, public_key.as_slice())
}

#[cfg(test)]
pub fn seal(
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedMessage, &'static str> {
    let mut setup = setup_sender(public_key, info)?;
    let ciphertext = setup
        .context
        .seal(aad, plaintext)
        .map_err(|_| "hpke_seal_failed")?;
    Ok(SealedMessage {
        encapsulated_key: setup.encapsulated_key,
        ciphertext,
    })
}

pub fn setup_sender(public_key: &[u8], info: &[u8]) -> Result<SenderSetup, &'static str> {
    validate_length(public_key, PUBLIC_KEY_BYTES, "hpke_public_key_invalid")?;
    let (encapsulated_key, context) = suite()
        .setup_sender(
            &HpkePublicKey::new(public_key.to_vec()),
            info,
            None,
            None,
            None,
        )
        .map_err(|_| "hpke_setup_sender_failed")?;
    Ok(SenderSetup {
        encapsulated_key: encapsulated_key.to_vec(),
        context,
    })
}

pub fn open(
    private_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    validate_length(private_key, PRIVATE_KEY_BYTES, "hpke_private_key_invalid")?;
    validate_length(
        encapsulated_key,
        ENCAPSULATED_KEY_BYTES,
        "hpke_encapsulated_key_invalid",
    )?;
    suite()
        .open(
            encapsulated_key,
            &HpkePrivateKey::new(private_key.to_vec()),
            info,
            aad,
            ciphertext,
            None,
            None,
            None,
        )
        .map_err(|_| "hpke_open_failed")
}

fn suite() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::XWingDraft06,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

fn key_material(private_key: &[u8], public_key: &[u8]) -> Result<KeyMaterial, &'static str> {
    validate_length(private_key, PRIVATE_KEY_BYTES, "hpke_private_key_invalid")?;
    validate_length(public_key, PUBLIC_KEY_BYTES, "hpke_public_key_invalid")?;
    Ok(KeyMaterial {
        private_key: private_key.to_vec(),
        x25519_private_key: derive_x25519_private_key(private_key)?,
        public_key: public_key.to_vec(),
    })
}

fn derive_x25519_private_key(private_key: &[u8]) -> Result<Vec<u8>, &'static str> {
    validate_length(private_key, PRIVATE_KEY_BYTES, "hpke_private_key_invalid")?;
    let mut output = Shake256::default().chain(private_key).finalize_xof();
    let mut mlkem_seed = [0u8; 64];
    output.read(&mut mlkem_seed);
    let mut x25519_private_key = [0u8; X25519_PRIVATE_KEY_BYTES];
    output.read(&mut x25519_private_key);
    Ok(x25519_private_key.to_vec())
}

fn validate_length(value: &[u8], expected: usize, error: &'static str) -> Result<(), &'static str> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use x_wing::{EncapsulationKey, TryKeyInit};

    #[derive(Deserialize)]
    struct Draft04Vector {
        mode: u16,
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: String,
        #[serde(rename = "skRm")]
        private_key: String,
        #[serde(rename = "pkRm")]
        public_key: String,
        #[serde(rename = "ikmE")]
        sender_randomness: String,
        enc: String,
        shared_secret: String,
        key: String,
        base_nonce: String,
        exporter_secret: String,
        encryptions: Vec<Draft04Encryption>,
        exports: Vec<Draft04Export>,
    }

    #[derive(Deserialize)]
    struct Draft04Encryption {
        aad: String,
        ct: String,
        nonce: String,
        pt: String,
    }

    #[derive(Deserialize)]
    struct Draft04Export {
        exporter_context: String,
        #[serde(rename = "L")]
        length: usize,
        exported_value: String,
    }

    #[test]
    fn key_material_and_round_trip_use_the_pinned_suite() {
        let recipient = generate_key_material().unwrap();
        let sealed = seal(&recipient.public_key, b"info", b"aad", b"secret").unwrap();

        assert_eq!(recipient.private_key.len(), PRIVATE_KEY_BYTES);
        assert_eq!(recipient.x25519_private_key.len(), X25519_PRIVATE_KEY_BYTES);
        assert_eq!(recipient.public_key.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sealed.encapsulated_key.len(), ENCAPSULATED_KEY_BYTES);
        assert_eq!(
            open(
                &recipient.private_key,
                &sealed.encapsulated_key,
                b"info",
                b"aad",
                &sealed.ciphertext,
            )
            .unwrap(),
            b"secret"
        );
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert_eq!(
            derive_key_material(&[0; 31]).err(),
            Some("hpke_private_key_invalid")
        );
        assert_eq!(
            seal(&[0; 1215], b"", b"", b"").err(),
            Some("hpke_public_key_invalid")
        );
        assert_eq!(
            open(&[0; 32], &[0; 1119], b"", b"", b"").unwrap_err(),
            "hpke_encapsulated_key_invalid"
        );
    }

    #[test]
    fn draft04_appendix_a5_1_base_vector_opens_byte_exact() {
        let vector: Draft04Vector =
            serde_json::from_str(include_str!("../testdata/draft-ietf-hpke-pq-04-a5-1.json"))
                .unwrap();
        assert_eq!(
            (vector.mode, vector.kem_id, vector.kdf_id, vector.aead_id),
            (0, 0x647a, 0x0001, 0x0003)
        );

        let private_key = hex::decode(vector.private_key).unwrap();
        let public_key = hex::decode(vector.public_key).unwrap();
        assert_eq!(
            derive_key_material(&private_key).unwrap().public_key,
            public_key
        );

        let sender_randomness = hex::decode(vector.sender_randomness).unwrap();
        let encapsulation_key = EncapsulationKey::new_from_slice(&public_key).unwrap();
        let deterministic_randomness = sender_randomness.as_slice().try_into().unwrap();
        let (encapsulated_key, shared_secret) =
            encapsulation_key.encapsulate_deterministic(&deterministic_randomness);
        assert_eq!(encapsulated_key.as_slice(), hex::decode(&vector.enc).unwrap());
        assert_eq!(shared_secret.as_slice(), hex::decode(vector.shared_secret).unwrap());

        let encapsulated_key = hex::decode(&vector.enc).unwrap();
        let info = hex::decode(&vector.info).unwrap();
        let mut seal_context = suite()
            .setup_receiver(
                &encapsulated_key,
                &HpkePrivateKey::new(private_key.clone()),
                &info,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(seal_context.key(), hex::decode(vector.key).unwrap());
        assert_eq!(
            seal_context.nonce(),
            hex::decode(&vector.base_nonce).unwrap()
        );
        assert_eq!(
            seal_context.exporter_secret(),
            hex::decode(vector.exporter_secret).unwrap()
        );

        let mut receiver = suite()
            .setup_receiver(
                &encapsulated_key,
                &HpkePrivateKey::new(private_key),
                &info,
                None,
                None,
                None,
            )
            .unwrap();
        let base_nonce = hex::decode(vector.base_nonce).unwrap();
        for (sequence, encryption) in vector.encryptions.into_iter().enumerate() {
            assert_eq!(seal_context.sequence_number(), sequence as u64);
            assert_eq!(receiver.sequence_number(), sequence as u64);
            assert_eq!(
                nonce_for_sequence(&base_nonce, sequence as u64),
                hex::decode(&encryption.nonce).unwrap()
            );
            assert_eq!(
                seal_context
                    .seal(
                        &hex::decode(&encryption.aad).unwrap(),
                        &hex::decode(&encryption.pt).unwrap(),
                    )
                    .unwrap(),
                hex::decode(&encryption.ct).unwrap()
            );
            assert_eq!(
                receiver
                    .open(
                        &hex::decode(encryption.aad).unwrap(),
                        &hex::decode(encryption.ct).unwrap(),
                    )
                    .unwrap(),
                hex::decode(encryption.pt).unwrap()
            );
        }
        for export in vector.exports {
            let context = hex::decode(export.exporter_context).unwrap();
            let expected = hex::decode(export.exported_value).unwrap();
            assert_eq!(
                seal_context.export(&context, export.length).unwrap(),
                expected
            );
            assert_eq!(receiver.export(&context, export.length).unwrap(), expected);
        }
    }

    fn nonce_for_sequence(base_nonce: &[u8], sequence: u64) -> Vec<u8> {
        let mut nonce = base_nonce.to_vec();
        for (offset, byte) in sequence.to_be_bytes().iter().rev().enumerate() {
            let index = nonce.len() - 1 - offset;
            nonce[index] ^= byte;
        }
        nonce
    }
}
