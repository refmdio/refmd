use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
pub enum AssetScope<'a> {
    Global,
    User {
        owner_id: Uuid,
        share_token: Option<&'a str>,
    },
}

pub struct AssetSigner {
    key: Vec<u8>,
}

impl AssetSigner {
    pub fn new(secret: &str) -> Self {
        Self {
            key: secret.as_bytes().to_vec(),
        }
    }

    pub fn sign_url(
        &self,
        scope: AssetScope<'_>,
        plugin_id: &str,
        version: &str,
        relative_path: &str,
        ttl_secs: u64,
    ) -> String {
        let normalized_path = normalize_asset_path(relative_path);
        let expires_at = Utc::now().timestamp() + ttl_secs as i64;
        let payload = build_payload(scope, plugin_id, version, &normalized_path, expires_at);
        let signature = self.sign_payload(&payload);

        let scope_str = match scope {
            AssetScope::Global => "global",
            AssetScope::User { .. } => "user",
        };
        let mut url = format!(
            "/api/plugin-assets?scope={scope}&plugin={plugin}&version={version}&path={path}&exp={exp}&sig={sig}",
            scope = scope_str,
            plugin = urlencoding::encode(plugin_id),
            version = urlencoding::encode(version),
            path = urlencoding::encode(&normalized_path),
            exp = expires_at,
            sig = signature,
        );

        if let AssetScope::User {
            owner_id,
            share_token,
        } = scope
        {
            url.push_str("&owner=");
            url.push_str(&owner_id.to_string());
            if let Some(token) = share_token {
                url.push_str("&share=");
                url.push_str(&urlencoding::encode(token));
            }
        }

        url
    }

    pub fn verify_url(
        &self,
        scope: AssetScope<'_>,
        plugin_id: &str,
        version: &str,
        relative_path: &str,
        expires_at: i64,
        signature: &str,
    ) -> bool {
        if expires_at <= Utc::now().timestamp() {
            return false;
        }
        let normalized_path = normalize_asset_path(relative_path);
        let payload = build_payload(scope, plugin_id, version, &normalized_path, expires_at);
        self.verify_payload(&payload, signature)
    }

    fn sign_payload(&self, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac key");
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        URL_SAFE_NO_PAD.encode(signature)
    }

    fn verify_payload(&self, payload: &str, signature: &str) -> bool {
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        let mut mac = match HmacSha256::new_from_slice(&self.key) {
            Ok(mac) => mac,
            Err(_) => return false,
        };
        mac.update(payload.as_bytes());
        mac.verify_slice(&decoded).is_ok()
    }
}

fn build_payload(
    scope: AssetScope<'_>,
    plugin_id: &str,
    version: &str,
    path: &str,
    expires_at: i64,
) -> String {
    let (scope_tag, owner_str, share_str) = match scope {
        AssetScope::Global => ("global", String::new(), String::new()),
        AssetScope::User {
            owner_id,
            share_token,
        } => (
            "user",
            owner_id.to_string(),
            share_token.unwrap_or("").to_string(),
        ),
    };

    format!(
        "{scope}|{owner}|{plugin}|{version}|{path}|{exp}|{share}",
        scope = scope_tag,
        owner = owner_str,
        plugin = plugin_id,
        version = version,
        path = path,
        exp = expires_at,
        share = share_str
    )
}

fn normalize_asset_path(path: &str) -> String {
    let mut cleaned = path.trim();
    while let Some(stripped) = cleaned.strip_prefix("./") {
        cleaned = stripped;
    }
    cleaned = cleaned.trim_start_matches('/');
    cleaned = cleaned.trim();
    cleaned.to_string()
}
