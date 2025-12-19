use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct JwtClaims {
    pub sub: Uuid,
    pub workspace_id: Option<Uuid>,
    pub iat: usize,
    pub exp: usize,
    pub sid: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtDecodeError {
    Expired,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwtEncodeError;

pub trait JwtCodec: Send + Sync {
    fn decode(&self, token: &str) -> Result<JwtClaims, JwtDecodeError>;
    fn encode(&self, claims: &JwtClaims) -> Result<String, JwtEncodeError>;
}
