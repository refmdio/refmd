use serde::Serialize;
use utoipa::ToSchema;

use application::contracts::tags::TagItemDto;

#[derive(Serialize, ToSchema)]
pub struct TagItem {
    pub name: String,
    pub count: i64,
}

impl From<TagItemDto> for TagItem {
    fn from(d: TagItemDto) -> Self {
        TagItem {
            name: d.name,
            count: d.count,
        }
    }
}
