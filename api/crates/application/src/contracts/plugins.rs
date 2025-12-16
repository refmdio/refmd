use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecResult {
    pub ok: bool,
    pub data: Option<serde_json::Value>,
    pub effects: Vec<serde_json::Value>,
    pub error: Option<serde_json::Value>,
}
