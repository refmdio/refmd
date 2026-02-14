//! Macro for defining UUID-based ID newtypes.
//!
//! Eliminates boilerplate across `DocumentId`, `DeviceId`, `WorkspaceId`,
//! `RoleId`, `UserId`, and `SessionId`.

/// Define a UUID v7 newtype ID with standard derives and impls.
///
/// # Generated impls
/// - `new()` — fresh v7 UUID
/// - `from_uuid(Uuid)` / `as_uuid()` — conversion
/// - `Default` (delegates to `new`)
/// - `Display` (delegates to inner UUID)
/// - `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`
macro_rules! define_id {
    ($(#[$meta:meta])* $vis:vis $Name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash,
            serde::Serialize, serde::Deserialize,
        )]
        $vis struct $Name(uuid::Uuid);

        impl $Name {
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            pub fn from_uuid(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> uuid::Uuid {
                self.0
            }
        }

        impl Default for $Name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
