use application::identity::ports::jwt_codec::{
    JwtClaims, JwtCodec, JwtDecodeError, JwtEncodeError,
};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Hs256JwtCodec {
    secret: String,
}

impl Hs256JwtCodec {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WireClaims {
    sub: String,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    iat: usize,
    exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
}

impl JwtCodec for Hs256JwtCodec {
    fn decode(&self, token: &str) -> Result<JwtClaims, JwtDecodeError> {
        let decoded = jsonwebtoken::decode::<WireClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        );
        let claims = match decoded {
            Ok(data) => data.claims,
            Err(err) => {
                if matches!(err.kind(), ErrorKind::ExpiredSignature) {
                    return Err(JwtDecodeError::Expired);
                }
                return Err(JwtDecodeError::Invalid);
            }
        };

        let sub = Uuid::parse_str(&claims.sub).map_err(|_| JwtDecodeError::Invalid)?;
        let workspace_id = claims
            .workspace_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| JwtDecodeError::Invalid)?;
        let sid = claims
            .sid
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| JwtDecodeError::Invalid)?;

        Ok(JwtClaims {
            sub,
            workspace_id,
            iat: claims.iat,
            exp: claims.exp,
            sid,
        })
    }

    fn encode(&self, claims: &JwtClaims) -> Result<String, JwtEncodeError> {
        let wire = WireClaims {
            sub: claims.sub.to_string(),
            workspace_id: claims.workspace_id.map(|id| id.to_string()),
            iat: claims.iat,
            exp: claims.exp,
            sid: claims.sid.map(|id| id.to_string()),
        };
        jsonwebtoken::encode(
            &Header::default(),
            &wire,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|_| JwtEncodeError)
    }
}
