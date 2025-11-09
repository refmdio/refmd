use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserDto {
    pub id: Uuid,
    pub email: String,
    pub name: String,
}
