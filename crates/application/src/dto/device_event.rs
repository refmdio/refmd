//! Device event DTO for wire-format serialization
//!
//! Maintains the same JSON format as the original `DeviceEvent` (with `serde(tag)`)
//! while the domain `DeviceEvent` uses strong types.

use domain::DeviceEvent;
use serde::{Deserialize, Serialize};

/// Serializable device event DTO (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceEventDto {
    PendingCreated {
        pending_id: String,
        user_id: String,
        device_name: String,
        device_type: String,
        ip_address: Option<String>,
        expires_at: String,
    },
    PendingApproved {
        pending_id: String,
        user_id: String,
        device_id: String,
    },
    PendingRemoved {
        pending_id: String,
        user_id: String,
    },
    PendingExpired {
        pending_id: String,
        user_id: String,
    },
    TrustTransferNonceReady {
        user_id: String,
        new_device_id: String,
        nonce: String,
    },
}

impl From<DeviceEvent> for DeviceEventDto {
    fn from(event: DeviceEvent) -> Self {
        match event {
            DeviceEvent::PendingCreated {
                pending_id,
                user_id,
                device_name,
                device_type,
                ip_address,
                expires_at,
            } => DeviceEventDto::PendingCreated {
                pending_id: pending_id.to_string(),
                user_id: user_id.to_string(),
                device_name,
                device_type: device_type.as_str().to_string(),
                ip_address,
                expires_at: expires_at.to_rfc3339(),
            },
            DeviceEvent::PendingApproved {
                pending_id,
                user_id,
                device_id,
            } => DeviceEventDto::PendingApproved {
                pending_id: pending_id.to_string(),
                user_id: user_id.to_string(),
                device_id: device_id.to_string(),
            },
            DeviceEvent::PendingRemoved {
                pending_id,
                user_id,
            } => DeviceEventDto::PendingRemoved {
                pending_id: pending_id.to_string(),
                user_id: user_id.to_string(),
            },
            DeviceEvent::PendingExpired {
                pending_id,
                user_id,
            } => DeviceEventDto::PendingExpired {
                pending_id: pending_id.to_string(),
                user_id: user_id.to_string(),
            },
            DeviceEvent::TrustTransferNonceReady {
                user_id,
                new_device_id,
                nonce,
            } => DeviceEventDto::TrustTransferNonceReady {
                user_id: user_id.to_string(),
                new_device_id: new_device_id.to_string(),
                nonce: base64_url::encode(&nonce),
            },
        }
    }
}

impl From<&DeviceEvent> for DeviceEventDto {
    fn from(event: &DeviceEvent) -> Self {
        Self::from(event.clone())
    }
}

/// Parse a UUID string, returning a descriptive error on failure.
fn parse_uuid(field: &str, variant: &str, field_name: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(field).map_err(|e| {
        format!(
            "Dropping cross-instance {} event: invalid {}: {}",
            variant, field_name, e,
        )
    })
}

impl TryFrom<DeviceEventDto> for DeviceEvent {
    type Error = String;

    fn try_from(dto: DeviceEventDto) -> Result<Self, Self::Error> {
        use domain::encryption::DeviceId;
        use domain::identity::UserId;

        match dto {
            DeviceEventDto::PendingCreated {
                pending_id,
                user_id,
                device_name,
                device_type,
                ip_address,
                expires_at,
            } => {
                let pending_id = DeviceId::from_uuid(parse_uuid(
                    &pending_id,
                    "PendingCreated",
                    "pending_id",
                )?);
                let user_id =
                    UserId::from_uuid(parse_uuid(&user_id, "PendingCreated", "user_id")?);
                let device_type: domain::encryption::DeviceType =
                    device_type.parse().map_err(|e: domain::encryption::DeviceTypeError| {
                        format!(
                            "Dropping cross-instance PendingCreated event: invalid device_type: {}",
                            e
                        )
                    })?;
                let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        format!(
                            "Dropping cross-instance PendingCreated event: invalid expires_at: {}",
                            e
                        )
                    })?;
                Ok(DeviceEvent::PendingCreated {
                    pending_id,
                    user_id,
                    device_name,
                    device_type,
                    ip_address,
                    expires_at,
                })
            }
            DeviceEventDto::PendingApproved {
                pending_id,
                user_id,
                device_id,
            } => {
                let pending_id = DeviceId::from_uuid(parse_uuid(
                    &pending_id,
                    "PendingApproved",
                    "pending_id",
                )?);
                let user_id =
                    UserId::from_uuid(parse_uuid(&user_id, "PendingApproved", "user_id")?);
                let device_id = DeviceId::from_uuid(parse_uuid(
                    &device_id,
                    "PendingApproved",
                    "device_id",
                )?);
                Ok(DeviceEvent::PendingApproved {
                    pending_id,
                    user_id,
                    device_id,
                })
            }
            DeviceEventDto::PendingRemoved {
                pending_id,
                user_id,
            } => {
                let pending_id = DeviceId::from_uuid(parse_uuid(
                    &pending_id,
                    "PendingRemoved",
                    "pending_id",
                )?);
                let user_id =
                    UserId::from_uuid(parse_uuid(&user_id, "PendingRemoved", "user_id")?);
                Ok(DeviceEvent::PendingRemoved {
                    pending_id,
                    user_id,
                })
            }
            DeviceEventDto::PendingExpired {
                pending_id,
                user_id,
            } => {
                let pending_id = DeviceId::from_uuid(parse_uuid(
                    &pending_id,
                    "PendingExpired",
                    "pending_id",
                )?);
                let user_id =
                    UserId::from_uuid(parse_uuid(&user_id, "PendingExpired", "user_id")?);
                Ok(DeviceEvent::PendingExpired {
                    pending_id,
                    user_id,
                })
            }
            DeviceEventDto::TrustTransferNonceReady {
                user_id,
                new_device_id,
                nonce,
            } => {
                let user_id = UserId::from_uuid(parse_uuid(
                    &user_id,
                    "TrustTransferNonceReady",
                    "user_id",
                )?);
                let new_device_id = DeviceId::from_uuid(parse_uuid(
                    &new_device_id,
                    "TrustTransferNonceReady",
                    "new_device_id",
                )?);
                let nonce = base64_url::decode(&nonce).map_err(|e| {
                    format!(
                        "Dropping cross-instance TrustTransferNonceReady event: invalid nonce: {}",
                        e
                    )
                })?;
                if nonce.len() != 32 {
                    return Err(format!(
                        "Dropping cross-instance TrustTransferNonceReady event: invalid nonce length {} (expected 32)",
                        nonce.len()
                    ));
                }
                Ok(DeviceEvent::TrustTransferNonceReady {
                    user_id,
                    new_device_id,
                    nonce,
                })
            }
        }
    }
}
