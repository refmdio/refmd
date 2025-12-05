use crate::application::dto::shares::{ShareBrowseResponseDto, ShareBrowseTreeItemDto};
use crate::application::ports::shares_repository::SharesRepository;

pub struct BrowseShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> BrowseShare<'a, R> {
    pub async fn execute(&self, token: &str) -> anyhow::Result<Option<ShareBrowseResponseDto>> {
        let row = self.repo.resolve_share_by_token(token).await?;
        let (share_id, _perm, expires_at, shared_id, shared_type, _workspace_id) = match row {
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
            let mut tree = Vec::new();
            let doc_rows = self.repo.list_subtree_nodes(shared_id).await?;
            if let Some((id, title, typ, _parent_id, created_at, updated_at)) = doc_rows
                .into_iter()
                .find(|(id, _, _, _, _, _)| *id == shared_id)
            {
                tree.push(ShareBrowseTreeItemDto {
                    id,
                    title,
                    parent_id: None,
                    r#type: typ,
                    created_at,
                    updated_at,
                });
            } else {
                let fallback_title = self
                    .repo
                    .validate_share_token(token)
                    .await?
                    .map(|(_, _, _, title)| title)
                    .unwrap_or_default();
                tree.push(ShareBrowseTreeItemDto {
                    id: shared_id,
                    title: fallback_title,
                    parent_id: None,
                    r#type: shared_type.clone(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                });
            }
            return Ok(Some(ShareBrowseResponseDto { tree }));
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
