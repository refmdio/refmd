use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentValidationError {
    NotFound,
    Archived,
}

#[derive(Debug, Clone)]
pub struct ParentMeta {
    pub archived_at: Option<DateTime<Utc>>,
}

pub fn ensure_active_parent(meta: Option<ParentMeta>) -> Result<(), ParentValidationError> {
    match meta {
        Some(pm) => {
            if pm.archived_at.is_some() {
                Err(ParentValidationError::Archived)
            } else {
                Ok(())
            }
        }
        None => Err(ParentValidationError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_parent_ok() {
        let pm = ParentMeta { archived_at: None };
        assert_eq!(ensure_active_parent(Some(pm)), Ok(()));
    }

    #[test]
    fn archived_parent_rejected() {
        let pm = ParentMeta {
            archived_at: Some(Utc::now()),
        };
        assert_eq!(
            ensure_active_parent(Some(pm)),
            Err(ParentValidationError::Archived)
        );
    }

    #[test]
    fn missing_parent_rejected() {
        assert_eq!(ensure_active_parent(None), Err(ParentValidationError::NotFound));
    }
}
