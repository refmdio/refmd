use super::*;

pub(super) fn previous_path_from_payload(payload: Option<&Value>) -> Option<String> {
    payload
        .and_then(|p| p.get("previous_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub(super) fn is_not_found_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::NotFound)
    })
}
