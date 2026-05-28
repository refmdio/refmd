import type { Channel } from "phoenix";
import {
  createPhoenixJoinError,
  disableChannelAutoRejoin,
  getPhoenixJoinErrorReason,
  leavePhoenixChannel,
  notifyChannelClosedOnSocketClose,
  PhoenixChannelTransportError,
} from "@/shared/lib/ws/channel";
import { ensurePhoenixWsToken, getOrCreatePhoenixSocket } from "@/shared/lib/ws/socket";
import {
  clearAuthTransportNetworkFailure,
  recordAuthTransportNetworkFailure,
} from "@/shared/lib/ws/transport-coordinator";

interface SecurityNotificationChannelHandle {
  channel: Channel;
  dispose: () => void;
}

interface SharedUserSecurityNotificationsState {
  channel: Channel | null;
  joinPromise: Promise<Channel> | null;
  subscribers: Set<UserSecurityNotificationCallbacks>;
}

export class SecurityNotificationsJoinError extends Error {
  readonly reason: string | null;

  constructor(resp: unknown) {
    super(createPhoenixJoinError(resp).message);
    this.name = "SecurityNotificationsJoinError";
    this.reason = getPhoenixJoinErrorReason(resp);
  }
}

export interface SecurityNotificationPayload extends Record<string, unknown> {
  type: string;
  action_ref?: Record<string, unknown>;
}

export interface UserSecurityNotificationCallbacks {
  onPendingDeviceCreated?: () => void;
  onPendingDeviceRemoved?: () => void;
  onKekRotationNeeded?: (payload: Record<string, unknown>) => void;
  onPluginConsentRequired?: () => void;
  onError?: (reason: unknown) => void;
  onClose?: () => void;
}

export interface PendingRegistrationSecurityNotificationCallbacks {
  onApproved?: () => void;
  onExpired?: () => void;
  onRejected?: () => void;
  onError?: (reason: unknown) => void;
  onClose?: () => void;
}

export interface ScopedSecurityNotificationCallbacks {
  onNotification?: (payload: SecurityNotificationPayload) => void;
  onError?: (reason: unknown) => void;
  onClose?: () => void;
}

const sharedUserSecurityNotifications: SharedUserSecurityNotificationsState = {
  channel: null,
  joinPromise: null,
  subscribers: new Set(),
};

export async function joinUserSecurityNotifications(
  userId: string,
  callbacks: UserSecurityNotificationCallbacks,
): Promise<SecurityNotificationChannelHandle> {
  sharedUserSecurityNotifications.subscribers.add(callbacks);

  try {
    const channel = await getOrJoinSharedUserSecurityNotifications(userId);
    return {
      channel,
      dispose: () => {
        sharedUserSecurityNotifications.subscribers.delete(callbacks);
        if (sharedUserSecurityNotifications.subscribers.size === 0) {
          disposeSharedUserSecurityNotifications();
        }
      },
    };
  } catch (error) {
    sharedUserSecurityNotifications.subscribers.delete(callbacks);
    throw error;
  }
}

async function getOrJoinSharedUserSecurityNotifications(userId: string): Promise<Channel> {
  if (
    sharedUserSecurityNotifications.channel &&
    sharedUserSecurityNotifications.channel.state !== "closed" &&
    sharedUserSecurityNotifications.channel.state !== "errored"
  ) {
    return sharedUserSecurityNotifications.channel;
  }

  if (sharedUserSecurityNotifications.joinPromise) {
    return sharedUserSecurityNotifications.joinPromise;
  }

  sharedUserSecurityNotifications.joinPromise = joinSecurityNotificationsChannel(
    `security:user:${userId}`,
    {
      onError: (reason) => {
        const subscribers = [...sharedUserSecurityNotifications.subscribers];
        disposeSharedUserSecurityNotifications();
        for (const subscriber of subscribers) {
          subscriber.onError?.(reason);
        }
      },
      onClose: () => {
        const subscribers = [...sharedUserSecurityNotifications.subscribers];
        disposeSharedUserSecurityNotifications();
        for (const subscriber of subscribers) {
          subscriber.onClose?.();
        }
      },
    },
  )
    .then((channel) => {
      sharedUserSecurityNotifications.channel = channel;
      channel.on<SecurityNotificationPayload>("notification", (payload) => {
        for (const subscriber of sharedUserSecurityNotifications.subscribers) {
          dispatchUserNotification(payload, subscriber);
        }
      });
      return channel;
    })
    .finally(() => {
      sharedUserSecurityNotifications.joinPromise = null;
    });

  return sharedUserSecurityNotifications.joinPromise;
}

function dispatchUserNotification(
  payload: SecurityNotificationPayload,
  callbacks: UserSecurityNotificationCallbacks,
): void {
  if (payload.type === "device.pending_approval") {
    callbacks.onPendingDeviceCreated?.();
    return;
  }

  if (payload.type === "device.pending_removed") {
    callbacks.onPendingDeviceRemoved?.();
    return;
  }

  if (payload.type === "workspace.kek_rotation_needed") {
    callbacks.onKekRotationNeeded?.(payload.action_ref ?? {});
    return;
  }

  if (payload.type === "plugin.consent_required") {
    callbacks.onPluginConsentRequired?.();
  }
}

function disposeSharedUserSecurityNotifications(): void {
  const channel = sharedUserSecurityNotifications.channel;
  sharedUserSecurityNotifications.channel = null;
  sharedUserSecurityNotifications.joinPromise = null;
  if (channel) {
    leavePhoenixChannel(channel);
  }
}

export async function joinPendingRegistrationSecurityNotifications(
  registrationId: string,
  callbacks: PendingRegistrationSecurityNotificationCallbacks,
): Promise<SecurityNotificationChannelHandle> {
  const channel = await joinSecurityNotificationsChannel(
    `security:pending_registration:${registrationId}`,
    callbacks,
    (registrationChannel) => {
      registrationChannel.on<SecurityNotificationPayload>("notification", (payload) => {
        if (payload.type === "device.registration_approved") {
          callbacks.onApproved?.();
        } else if (payload.type === "device.registration_expired") {
          callbacks.onExpired?.();
        } else if (payload.type === "device.registration_rejected") {
          callbacks.onRejected?.();
        }
      });
    },
  );

  return createHandle(channel);
}

export async function joinDeviceSecurityNotifications(
  deviceId: string,
  callbacks: ScopedSecurityNotificationCallbacks,
): Promise<SecurityNotificationChannelHandle> {
  return joinScopedSecurityNotifications(`security:device:${deviceId}`, callbacks);
}

export async function joinWorkspaceSecurityNotifications(
  workspaceId: string,
  callbacks: ScopedSecurityNotificationCallbacks,
): Promise<SecurityNotificationChannelHandle> {
  return joinScopedSecurityNotifications(`security:workspace:${workspaceId}`, callbacks);
}

async function joinScopedSecurityNotifications(
  topic: string,
  callbacks: ScopedSecurityNotificationCallbacks,
): Promise<SecurityNotificationChannelHandle> {
  const channel = await joinSecurityNotificationsChannel(topic, callbacks, (scopedChannel) => {
    scopedChannel.on<SecurityNotificationPayload>("notification", (payload) => {
      callbacks.onNotification?.(payload);
    });
  });

  return createHandle(channel);
}

async function joinSecurityNotificationsChannel(
  topic: string,
  callbacks: Pick<UserSecurityNotificationCallbacks, "onError" | "onClose">,
  registerHandlers?: (channel: Channel) => void,
): Promise<Channel> {
  await ensurePhoenixWsToken("user");

  const socket = getOrCreatePhoenixSocket("user");
  const channel = socket.channel(topic, {});
  disableChannelAutoRejoin(channel);
  notifyChannelClosedOnSocketClose(socket, channel, () => callbacks.onClose?.());

  channel.onError((reason) => callbacks.onError?.(reason ?? "connection_error"));
  channel.onClose(() => callbacks.onClose?.());
  registerHandlers?.(channel);

  return new Promise<Channel>((resolve, reject) => {
    channel
      .join()
      .receive("ok", () => {
        clearAuthTransportNetworkFailure();
        resolve(channel);
      })
      .receive("error", (resp) => {
        leavePhoenixChannel(channel);
        reject(new SecurityNotificationsJoinError(resp));
      })
      .receive("timeout", () => {
        recordAuthTransportNetworkFailure();
        leavePhoenixChannel(channel);
        reject(
          new PhoenixChannelTransportError(
            "join_timeout",
            "Security notification channel join timed out",
          ),
        );
      });
  });
}

function createHandle(channel: Channel): SecurityNotificationChannelHandle {
  let disposed = false;

  return {
    channel,
    dispose: () => {
      if (disposed) return;
      disposed = true;
      leavePhoenixChannel(channel);
    },
  };
}
