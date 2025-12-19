use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiTokenSubject {
    pub owner_id: Uuid,
    pub workspace_id: Uuid,
}
