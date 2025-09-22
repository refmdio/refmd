use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

fn derive_key(secret: &str) -> Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let out = hasher.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    Key::<Aes256Gcm>::from_slice(&k).clone()
}

pub fn encrypt_string(secret: &str, plaintext: &str) -> anyhow::Result<String> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new(&key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt failed: {}", e))?;
    let n_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
    let c_b64 = base64::engine::general_purpose::STANDARD.encode(ct);
    Ok(format!("v1:{}:{}", n_b64, c_b64))
}

pub fn decrypt_string(secret: &str, ciphertext: &str) -> anyhow::Result<String> {
    // Support plaintext (not encrypted) for backward compatibility
    if !ciphertext.starts_with("v1:") {
        return Ok(ciphertext.to_string());
    }
    let parts: Vec<&str> = ciphertext.splitn(3, ':').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid format");
    }
    let n_b64 = parts[1];
    let c_b64 = parts[2];
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(n_b64)
        .map_err(|e| anyhow::anyhow!("b64 decode nonce: {}", e))?;
    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(c_b64)
        .map_err(|e| anyhow::anyhow!("b64 decode ct: {}", e))?;
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("decrypt failed: {}", e))?;
    Ok(String::from_utf8(pt).unwrap_or_default())
}

pub fn encrypt_auth_data(secret: &str, auth_data: &serde_json::Value) -> serde_json::Value {
    match auth_data {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if (k == "token" || k == "private_key") && v.is_string() {
                    let s = v.as_str().unwrap_or("");
                    // idempotent: avoid double-encryption
                    let enc = if s.starts_with("v1:") {
                        s.to_string()
                    } else {
                        encrypt_string(secret, s).unwrap_or_default()
                    };
                    out.insert(k.clone(), serde_json::Value::String(enc));
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        _ => auth_data.clone(),
    }
}

pub fn decrypt_auth_data(secret: &str, auth_data: &serde_json::Value) -> serde_json::Value {
    match auth_data {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if (k == "token" || k == "private_key") && v.is_string() {
                    let s = v.as_str().unwrap_or("");
                    let dec = decrypt_string(secret, s).unwrap_or_else(|_| s.to_string());
                    out.insert(k.clone(), serde_json::Value::String(dec));
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        _ => auth_data.clone(),
    }
}
