use anyhow::Context;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::identity::dtos::UserShortcutProfileDto;
use crate::identity::ports::user_shortcuts::user_shortcut_repository::UserShortcutRepository;

#[derive(Debug, Error)]
pub enum UpdateUserShortcutsError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Storage(#[from] anyhow::Error),
}

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
    ) -> Result<UserShortcutProfileDto, UpdateUserShortcutsError> {
        let bindings = match payload.bindings {
            Value::Object(map) => Value::Object(map),
            Value::Null => Value::Object(Map::new()),
            _ => {
                return Err(UpdateUserShortcutsError::Validation(
                    "bindings must be a JSON object".into(),
                ));
            }
        };

        if let Some(leader) = payload.leader_key.as_deref()
            && leader.len() > 16
        {
            return Err(UpdateUserShortcutsError::Validation(
                "leader key is too long".into(),
            ));
        }

        let encoded = serde_json::to_vec(&bindings)
            .context("serialize bindings")
            .map_err(UpdateUserShortcutsError::Storage)?;
        if encoded.len() > self.max_payload_bytes {
            return Err(UpdateUserShortcutsError::Validation(
                "bindings payload too large".into(),
            ));
        }

        let profile = self
            .repo
            .upsert(user_id, bindings, payload.leader_key)
            .await
            .map_err(|err| UpdateUserShortcutsError::Storage(anyhow::Error::from(err)))?;
        Ok(UserShortcutProfileDto::from(profile))
    }
}
