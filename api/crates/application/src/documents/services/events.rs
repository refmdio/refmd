use tracing::warn;
use uuid::Uuid;

use super::DocumentService;

impl DocumentService {
    pub(super) async fn record_event(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        event_type: &'static str,
        payload: Option<serde_json::Value>,
    ) {
        if let Err(err) = self
            .events
            .append(workspace_id, doc_id, event_type, payload)
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "doc_event_log_append_failed"
            );
        }
    }
}
