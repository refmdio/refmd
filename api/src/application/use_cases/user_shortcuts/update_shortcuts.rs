use anyhow::{Context, anyhow, bail};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::application::ports::user_shortcut_repository::{
    UserShortcutProfile, UserShortcutRepository,
};

#[derive(Debug, Clone)]
pub struct UpdateUserShortcutsPayload {
    pub bindings: Value,
    pub leader_key: Option<String>,
}

pub struct UpdateUserShortcuts<'a, R: UserShortcutRepository + ?Sized> {
    pub repo: &'a R,
    pub max_payload_bytes: usize,
}

impl<'a, R> UpdateUserShortcuts<'a, R>
where
    R: UserShortcutRepository + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        payload: UpdateUserShortcutsPayload,
    ) -> anyhow::Result<UserShortcutProfile> {
        let bindings = match payload.bindings {
            Value::Object(map) => Value::Object(map),
            Value::Null => Value::Object(Map::new()),
            _ => bail!("bindings must be a JSON object"),
        };

        if let Some(ref leader) = payload.leader_key {
            if leader.len() > 16 {
                bail!("leader key is too long");
            }
        }

        let encoded = serde_json::to_vec(&bindings).context("serialize bindings")?;
        if encoded.len() > self.max_payload_bytes {
            return Err(anyhow!("bindings payload too large"));
        }

        self.repo
            .upsert(user_id, bindings, payload.leader_key)
            .await
    }
}
