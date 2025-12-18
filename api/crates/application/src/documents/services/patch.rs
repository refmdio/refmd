use crate::core::services::errors::ServiceError;

#[derive(Debug, Clone)]
pub enum DocumentPatchOperation {
    Insert {
        offset: usize,
        text: String,
    },
    Delete {
        offset: usize,
        length: usize,
    },
    Replace {
        offset: usize,
        length: usize,
        text: String,
    },
}

pub(super) fn apply_patch_operations(
    initial: &str,
    operations: &[DocumentPatchOperation],
) -> Result<String, ServiceError> {
    let mut chars: Vec<char> = initial.chars().collect();
    for operation in operations {
        match operation {
            DocumentPatchOperation::Insert { offset, text } => {
                splice_chars(&mut chars, *offset, 0, text)?;
            }
            DocumentPatchOperation::Delete { offset, length } => {
                splice_chars(&mut chars, *offset, *length, "")?;
            }
            DocumentPatchOperation::Replace {
                offset,
                length,
                text,
            } => {
                splice_chars(&mut chars, *offset, *length, text)?;
            }
        }
    }
    Ok(chars.into_iter().collect())
}

fn splice_chars(
    chars: &mut Vec<char>,
    offset: usize,
    length: usize,
    replacement: &str,
) -> Result<(), ServiceError> {
    if offset > chars.len() {
        return Err(ServiceError::BadRequest("patch_offset_out_of_bounds"));
    }
    let end = offset
        .checked_add(length)
        .ok_or(ServiceError::BadRequest("patch_length_overflow"))?;
    if end > chars.len() {
        return Err(ServiceError::BadRequest("patch_range_out_of_bounds"));
    }
    chars.splice(offset..end, replacement.chars());
    Ok(())
}
