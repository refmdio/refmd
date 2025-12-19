use super::*;
use domain::documents::doc_type::DocumentType;

#[derive(Debug, Clone)]
pub(super) struct ResolvedDocument {
    pub(super) id: Uuid,
    pub(super) doc_type: DocumentType,
    pub(super) path: Option<String>,
    pub(super) archived: bool,
}

impl ResolvedDocument {
    pub(super) fn new(
        id: Uuid,
        doc_type: DocumentType,
        path: Option<String>,
        archived: bool,
    ) -> Self {
        Self {
            id,
            doc_type,
            path,
            archived,
        }
    }

    pub(super) fn is_folder(&self) -> bool {
        self.doc_type.is_folder()
    }

    pub(super) fn is_archived(&self) -> bool {
        self.archived
    }
}

impl From<DomainDocument> for ResolvedDocument {
    fn from(value: DomainDocument) -> Self {
        Self::new(
            value.id(),
            value.doc_type(),
            value.path().map(str::to_string),
            value.archived_at().is_some(),
        )
    }
}
