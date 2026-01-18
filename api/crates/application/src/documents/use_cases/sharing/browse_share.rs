use std::collections::HashMap;

use base64::Engine;

use crate::documents::dtos::{ShareBrowseResponseDto, ShareBrowseTreeItemDto};
use crate::documents::ports::sharing::shares_repository::SharesRepository;
use domain::documents::doc_type::DocumentType;
use domain::documents::share;

pub struct BrowseShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> BrowseShare<'a, R> {
    pub async fn execute(&self, token: &str) -> anyhow::Result<Option<ShareBrowseResponseDto>> {
        let ctx = match self.repo.resolve_share_by_token(token).await? {
            Some(ctx) => ctx,
            None => return Ok(None),
        };
        if share::is_expired(ctx.expires_at.as_ref(), chrono::Utc::now()) {
            return Ok(None);
        }
        // If token targets a document (not folder), return single node
        if !ctx.shared_type.is_folder() {
            let mut tree = Vec::new();
            let doc_rows = self.repo.list_subtree_nodes(ctx.shared_id).await?;
            if let Some(node) = doc_rows.into_iter().find(|n| n.id == ctx.shared_id) {
                tree.push(ShareBrowseTreeItemDto {
                    id: node.id,
                    title: node.title.into_string(),
                    parent_id: None,
                    r#type: node.document_type.as_str().to_string(),
                    created_at: node.created_at,
                    updated_at: node.updated_at,
                    share_token: None,
                    encrypted_dek: None,
                });
            } else {
                let fallback_title = self
                    .repo
                    .validate_share_token(token)
                    .await?
                    .map(|doc| doc.title.into_string())
                    .unwrap_or_default();
                tree.push(ShareBrowseTreeItemDto {
                    id: ctx.shared_id,
                    title: fallback_title,
                    parent_id: None,
                    r#type: ctx.shared_type.as_str().to_string(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    share_token: None,
                    encrypted_dek: None,
                });
            }
            return Ok(Some(ShareBrowseResponseDto { tree }));
        }
        // Folder: list subtree and filter to materialized shares under this folder share
        let rows = self.repo.list_subtree_nodes(ctx.shared_id).await?;

        // Get child share info (token + encrypted DEK) for documents
        let child_info = self.repo.list_child_share_info(ctx.share_id).await?;
        let child_info_map: HashMap<_, _> = child_info
            .into_iter()
            .map(|info| (info.document_id, (info.token, info.encrypted_dek)))
            .collect();

        let tree: Vec<ShareBrowseTreeItemDto> = rows
            .into_iter()
            .filter_map(|node| {
                // For documents, check if they have a materialized child share
                if node.document_type == DocumentType::Document {
                    let child = child_info_map.get(&node.id)?;
                    let (child_token, encrypted_dek) = child;
                    return Some(ShareBrowseTreeItemDto {
                        id: node.id,
                        title: node.title.into_string(),
                        parent_id: node.parent_id,
                        r#type: node.document_type.as_str().to_string(),
                        created_at: node.created_at,
                        updated_at: node.updated_at,
                        share_token: Some(child_token.clone()),
                        encrypted_dek: encrypted_dek.as_ref().map(|dek| {
                            base64::engine::general_purpose::STANDARD.encode(dek)
                        }),
                    });
                }
                // For folders, include without child share info
                Some(ShareBrowseTreeItemDto {
                    id: node.id,
                    title: node.title.into_string(),
                    parent_id: node.parent_id,
                    r#type: node.document_type.as_str().to_string(),
                    created_at: node.created_at,
                    updated_at: node.updated_at,
                    share_token: None,
                    encrypted_dek: None,
                })
            })
            .collect();
        Ok(Some(ShareBrowseResponseDto { tree }))
    }
}
