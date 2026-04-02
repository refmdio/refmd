type DocumentSyncErrorCode =
  | "rollback_attack"
  | "unauthorized"
  | "verification_failed"
  | "channel_error"
  | "server_unreachable"
  | "unknown";

export class DocumentSyncError extends Error {
  readonly code: DocumentSyncErrorCode;

  constructor(code: DocumentSyncErrorCode, message: string) {
    super(message);
    this.name = "DocumentSyncError";
    this.code = code;
  }
}

type DocumentChannelErrorCode =
  | "not_a_member"
  | "permission_denied"
  | "document_not_found"
  | "document_error"
  | "connection_cap_evict";

export class DocumentChannelError extends Error {
  readonly code: DocumentChannelErrorCode;

  constructor(code: DocumentChannelErrorCode, message: string = code) {
    super(message);
    this.name = "DocumentChannelError";
    this.code = code;
  }
}

export function createDocumentSyncFailure(
  reason: string,
  error?: unknown,
): DocumentSyncError | DocumentChannelError {
  if (error instanceof DocumentSyncError || error instanceof DocumentChannelError) {
    return error;
  }

  const message = error instanceof Error ? error.message : reason;
  const reasonMessage = reason || message;

  switch (reason) {
    case "unauthorized":
      return new DocumentSyncError("unauthorized", reasonMessage);
    case "verification_failed":
      return new DocumentSyncError("verification_failed", message);
    case "rollback_attack":
      return new DocumentSyncError("rollback_attack", message);
    case "not_a_member":
    case "permission_denied":
    case "document_not_found":
    case "document_error":
    case "connection_cap_evict":
      return new DocumentChannelError(reason as DocumentChannelErrorCode, reasonMessage);
    case "disconnected":
    case "connection_error":
    case "reconnect_failed":
    case "reconnect_exhausted":
      return new DocumentSyncError("server_unreachable", message);
    case "snapshot_mismatch":
      return new DocumentSyncError("channel_error", reasonMessage);
    case "initial_load_failed":
      if (error instanceof TypeError) {
        return new DocumentSyncError("server_unreachable", message);
      }
      return new DocumentSyncError("unknown", message);
    default:
      return new DocumentSyncError("unknown", message);
  }
}
