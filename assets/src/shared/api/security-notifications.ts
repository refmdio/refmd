import { client, throwIfError, withUserRrpParams } from "./core";
import { verifyAndPinAuditCheckpoint } from "@/shared/lib/anti-rollback/audit-checkpoint-pin";

type ApiResult = { data?: unknown; error?: unknown; response: Response };
const apiGet = client.GET as unknown as (
  path: string,
  options: Record<string, unknown>,
) => Promise<ApiResult>;
const apiPatch = client.PATCH as unknown as (
  path: string,
  options: Record<string, unknown>,
) => Promise<ApiResult>;

export interface SecurityNotificationInfo {
  id: string;
  type: string;
  severity: string;
  action_ref?: Record<string, unknown>;
  read_at?: string | null;
  dismissed_at?: string | null;
  acted_at?: string | null;
  expires_at?: string | null;
  audit_checkpoint: Record<string, unknown>;
}

interface SecurityNotificationEnvelope {
  notification?: SecurityNotificationInfo;
  notifications?: readonly SecurityNotificationInfo[];
}

interface SecurityNotificationListOptions {
  recipientKind?: "user" | "device" | "workspace_role" | "pending_registration";
  recipientId?: string;
}

export const securityNotificationsApi = {
  list: async (
    options: SecurityNotificationListOptions = {},
  ): Promise<readonly SecurityNotificationInfo[]> => {
    const query =
      options.recipientKind && options.recipientId
        ? {
            recipient_kind: options.recipientKind,
            recipient_id: options.recipientId,
          }
        : undefined;
    const envelope = throwIfError(
      await apiGet("/api/security/notifications", {
        params: query ? withUserRrpParams({ query }) : withUserRrpParams(),
      }),
    ) as SecurityNotificationEnvelope;

    const notifications = Array.isArray(envelope.notifications) ? envelope.notifications : [];
    await Promise.all(
      notifications.map((notification) =>
        verifyAndPinAuditCheckpoint(notification.audit_checkpoint),
      ),
    );
    return notifications;
  },
  markRead: async (notificationId: string): Promise<SecurityNotificationInfo> => {
    const envelope = throwIfError(
      await apiPatch("/api/security/notifications/{notification_id}/read", {
        params: withUserRrpParams({ path: { notification_id: notificationId } }),
      }),
    ) as SecurityNotificationEnvelope;
    if (!envelope.notification) throw new Error("security_notification_missing");
    await verifyAndPinAuditCheckpoint(envelope.notification.audit_checkpoint);
    return envelope.notification;
  },
  dismiss: async (notificationId: string): Promise<SecurityNotificationInfo> => {
    const envelope = throwIfError(
      await apiPatch("/api/security/notifications/{notification_id}/dismiss", {
        params: withUserRrpParams({ path: { notification_id: notificationId } }),
      }),
    ) as SecurityNotificationEnvelope;
    if (!envelope.notification) throw new Error("security_notification_missing");
    await verifyAndPinAuditCheckpoint(envelope.notification.audit_checkpoint);
    return envelope.notification;
  },
};

export const securityCheckpointsApi = {
  current: async (): Promise<{
    user_audit_checkpoint: Record<string, unknown>;
    workspace_audit_checkpoints: Array<{
      workspace_id: string;
      audit_checkpoint: Record<string, unknown>;
    }>;
  }> =>
    throwIfError(
      await apiGet("/api/security/audit-checkpoints", {
        params: withUserRrpParams(),
      }),
    ) as never,
};
