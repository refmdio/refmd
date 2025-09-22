use crate::application::dto::shares::{ShareBrowseResponseDto, ShareBrowseTreeItemDto};
use crate::application::ports::shares_repository::SharesRepository;

pub struct BrowseShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> BrowseShare<'a, R> {
    pub async fn execute(&self, token: &str) -> anyhow::Result<Option<ShareBrowseResponseDto>> {
        let row = self.repo.resolve_share_by_token(token).await?;
        let (share_id, _perm, expires_at, shared_id, shared_type) = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        if let Some(exp) = expires_at {
            if exp < chrono::Utc::now() {
                return Ok(None);
            }
        }
        // If token targets a document (not folder), return single node
        if shared_type != "folder" {
            let items = vec![ShareBrowseTreeItemDto {
                id: shared_id,
                title: String::new(),
                parent_id: None,
                r#type: "document".into(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }];
            return Ok(Some(ShareBrowseResponseDto { tree: items }));
        }
        // Folder: list subtree and filter to materialized shares under this folder share
        let rows = self.repo.list_subtree_nodes(shared_id).await?;
        let allowed = self.repo.list_materialized_children(share_id).await?;
        let tree: Vec<ShareBrowseTreeItemDto> = rows
            .into_iter()
            .filter_map(|(id, title, typ, parent_id, created_at, updated_at)| {
                if typ == "document" && !allowed.contains(&id) {
                    return None;
                }
                Some(ShareBrowseTreeItemDto {
                    id,
                    title,
                    parent_id,
                    r#type: typ,
                    created_at,
                    updated_at,
                })
            })
            .collect();
        Ok(Some(ShareBrowseResponseDto { tree }))
    }
}
