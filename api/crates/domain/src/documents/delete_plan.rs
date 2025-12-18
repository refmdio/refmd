use uuid::Uuid;

use crate::documents::doc_type::DocumentType;
use crate::documents::meta::DocMeta;

#[derive(Debug, Clone)]
pub struct DeleteNode {
    pub id: Uuid,
    pub doc_type: DocumentType,
    pub meta: DocMeta,
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DeleteEntry {
    pub doc_id: Uuid,
    pub doc_type: DocumentType,
    pub meta: DocMeta,
    pub attachments: Vec<String>,
    pub reason: &'static str,
}

pub fn build_delete_plan(
    root_id: Uuid,
    root_meta: DocMeta,
    nodes: Vec<DeleteNode>,
) -> anyhow::Result<Vec<DeleteEntry>> {
    if root_meta.doc_type != DocumentType::Folder {
        let attachments = nodes
            .into_iter()
            .find(|n| n.id == root_id)
            .map(|n| n.attachments)
            .unwrap_or_default();
        return Ok(vec![DeleteEntry {
            doc_id: root_id,
            doc_type: root_meta.doc_type.clone(),
            meta: root_meta,
            attachments,
            reason: "delete_document",
        }]);
    }

    let mut entries = Vec::new();
    for node in nodes {
        let meta = if node.id == root_id {
            root_meta.clone()
        } else {
            node.meta
        };
        let reason = if node.id == root_id {
            "delete_folder"
        } else if node.doc_type == DocumentType::Folder {
            "delete_folder_descendant"
        } else {
            "delete_document_descendant"
        };
        entries.push(DeleteEntry {
            doc_id: node.id,
            doc_type: node.doc_type,
            meta,
            attachments: node.attachments,
            reason,
        });
    }
    entries.sort_by(|a, b| {
        let depth_a = path_depth(a.meta.desired_path.as_str());
        let depth_b = path_depth(b.meta.desired_path.as_str());
        depth_b
            .cmp(&depth_a)
            .then_with(|| is_folder(a.doc_type).cmp(&is_folder(b.doc_type)))
    });
    Ok(entries)
}

fn path_depth(path: &str) -> usize {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

fn is_folder(doc_type: DocumentType) -> usize {
    if doc_type.is_folder() { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::documents::doc_type::DocumentType;

    #[test]
    fn sorts_by_depth_desc_then_folder_last() {
        let root_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let root_meta = DocMeta {
            workspace_id,
            doc_type: DocumentType::Folder,
            path: Some(format!("{}/", workspace_id)),
            slug: crate::documents::path::Slug::new("root".to_string()).unwrap(),
            desired_path: crate::documents::path::DesiredPath::root(),
            title: crate::documents::title::Title::new("root"),
            archived_at: None,
        };
        let doc1 = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let leaf = Uuid::new_v4();
        let nodes = vec![
            DeleteNode {
                id: root_id,
                doc_type: DocumentType::Folder,
                meta: root_meta.clone(),
                attachments: vec![],
            },
            DeleteNode {
                id: doc1,
                doc_type: DocumentType::Document,
                meta: DocMeta {
                    workspace_id,
                    doc_type: DocumentType::Document,
                    path: Some(format!("{}/doc1", workspace_id)),
                    slug: crate::documents::path::Slug::new("doc1".to_string()).unwrap(),
                    desired_path: crate::documents::path::DesiredPath::new("doc1"),
                    title: crate::documents::title::Title::new("doc1"),
                    archived_at: None,
                },
                attachments: vec![],
            },
            DeleteNode {
                id: folder,
                doc_type: DocumentType::Folder,
                meta: DocMeta {
                    workspace_id,
                    doc_type: DocumentType::Folder,
                    path: Some(format!("{}/folder", workspace_id)),
                    slug: crate::documents::path::Slug::new("folder".to_string()).unwrap(),
                    desired_path: crate::documents::path::DesiredPath::new("folder"),
                    title: crate::documents::title::Title::new("folder"),
                    archived_at: None,
                },
                attachments: vec![],
            },
            DeleteNode {
                id: leaf,
                doc_type: DocumentType::Document,
                meta: DocMeta {
                    workspace_id,
                    doc_type: DocumentType::Document,
                    path: Some(format!("{}/folder/leaf", workspace_id)),
                    slug: crate::documents::path::Slug::new("leaf".to_string()).unwrap(),
                    desired_path: crate::documents::path::DesiredPath::new("folder/leaf"),
                    title: crate::documents::title::Title::new("leaf"),
                    archived_at: None,
                },
                attachments: vec![],
            },
        ];

        let entries = build_delete_plan(root_id, root_meta, nodes).unwrap();

        // Expected order: deepest doc leaf, sibling doc, folder, root folder last
        assert_eq!(entries[0].doc_id, leaf);
        assert_eq!(entries[1].doc_id, doc1);
        assert_eq!(entries[2].doc_id, folder);
        assert_eq!(entries[3].doc_id, root_id);
    }
}
