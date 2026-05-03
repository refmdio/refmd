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

interface DeviceEventChannelHandle {
  channel: Channel;
  dispose: () => void;
}

interface SharedUserDeviceEventsState {
  channel: Channel | null;
  joinPromise: Promise<Channel> | null;
  subscribers: Set<UserDeviceEventsCallbacks>;
}

export class DeviceEventsJoinError extends Error {
  readonly reason: string | null;

  constructor(resp: unknown) {
    super(createPhoenixJoinError(resp).message);
    this.name = "DeviceEventsJoinError";
    this.reason = getPhoenixJoinErrorReason(resp);
  }
}

export interface KekRotationNeededPayload extends Record<string, unknown> {
  workspace_id?: string;
  current_kek_version?: number;
}

export interface TrustTransferNonceReadyPayload extends Record<string, unknown> {
  new_device_id?: string;
  nonce?: string;
}

export interface UserDeviceEventsCallbacks {
  onPendingDeviceCreated?: () => void;
  onPendingDeviceRemoved?: () => void;
  onKekRotationNeeded?: (payload: KekRotationNeededPayload) => void;
  onTrustTransferNonceReady?: (payload: TrustTransferNonceReadyPayload) => void;
  onError?: (reason: unknown) => void;
  onClose?: () => void;
}

export interface RegistrationDeviceEventsCallbacks {
  onApproved?: () => void;
  onExpired?: () => void;
  onRejected?: () => void;
  onError?: (reason: unknown) => void;
  onClose?: () => void;
}

const sharedUserDeviceEvents: SharedUserDeviceEventsState = {
  channel: null,
  joinPromise: null,
  subscribers: new Set(),
};

export async function joinUserDeviceEvents(
  callbacks: UserDeviceEventsCallbacks,
): Promise<DeviceEventChannelHandle> {
  sharedUserDeviceEvents.subscribers.add(callbacks);

  try {
    const channel = await getOrJoinSharedUserDeviceEvents();
    return {
      channel,
      dispose: () => {
        sharedUserDeviceEvents.subscribers.delete(callbacks);
        if (sharedUserDeviceEvents.subscribers.size === 0) {
          disposeSharedUserDeviceEvents();
        }
      },
    };
  } catch (error) {
    sharedUserDeviceEvents.subscribers.delete(callbacks);
    throw error;
  }
}

async function getOrJoinSharedUserDeviceEvents(): Promise<Channel> {
  if (
    sharedUserDeviceEvents.channel &&
    sharedUserDeviceEvents.channel.state !== "closed" &&
    sharedUserDeviceEvents.channel.state !== "errored"
  ) {
    return sharedUserDeviceEvents.channel;
  }

  if (sharedUserDeviceEvents.joinPromise) {
    return sharedUserDeviceEvents.joinPromise;
  }

  sharedUserDeviceEvents.joinPromise = joinDeviceEventsChannel("devices:user", {
    onError: (reason) => {
      const subscribers = [...sharedUserDeviceEvents.subscribers];
      disposeSharedUserDeviceEvents();
      for (const subscriber of subscribers) {
        subscriber.onError?.(reason);
      }
    },
    onClose: () => {
      const subscribers = [...sharedUserDeviceEvents.subscribers];
      disposeSharedUserDeviceEvents();
      for (const subscriber of subscribers) {
        subscriber.onClose?.();
      }
    },
  })
    .then((channel) => {
      sharedUserDeviceEvents.channel = channel;
      channel.on("pending_device_created", () => {
        for (const subscriber of sharedUserDeviceEvents.subscribers) {
          subscriber.onPendingDeviceCreated?.();
        }
      });
      channel.on("pending_device_removed", () => {
        for (const subscriber of sharedUserDeviceEvents.subscribers) {
          subscriber.onPendingDeviceRemoved?.();
        }
      });
      channel.on<KekRotationNeededPayload>("kek_rotation_needed", (payload) => {
        for (const subscriber of sharedUserDeviceEvents.subscribers) {
          subscriber.onKekRotationNeeded?.(payload);
        }
      });
      channel.on<TrustTransferNonceReadyPayload>("trust_transfer_nonce_ready", (payload) => {
        for (const subscriber of sharedUserDeviceEvents.subscribers) {
          subscriber.onTrustTransferNonceReady?.(payload);
        }
      });
      return channel;
    })
    .finally(() => {
      sharedUserDeviceEvents.joinPromise = null;
    });

  return sharedUserDeviceEvents.joinPromise;
}

function disposeSharedUserDeviceEvents(): void {
  const channel = sharedUserDeviceEvents.channel;
  sharedUserDeviceEvents.channel = null;
  sharedUserDeviceEvents.joinPromise = null;
  if (channel) {
    leavePhoenixChannel(channel);
  }
}

export async function joinRegistrationDeviceEvents(
  deviceId: string,
  callbacks: RegistrationDeviceEventsCallbacks,
): Promise<DeviceEventChannelHandle> {
  const channel = await joinDeviceEventsChannel(
    `devices:registration:${deviceId}`,
    callbacks,
    (registrationChannel) => {
      registrationChannel.on("pending_approved", () => callbacks.onApproved?.());
      registrationChannel.on("expired", () => callbacks.onExpired?.());
      registrationChannel.on("pending_rejected", () => callbacks.onRejected?.());
    },
  );

  return createHandle(channel);
}

async function joinDeviceEventsChannel(
  topic: string,
  callbacks: Pick<UserDeviceEventsCallbacks, "onError" | "onClose">,
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
        reject(new DeviceEventsJoinError(resp));
      })
      .receive("timeout", () => {
        recordAuthTransportNetworkFailure();
        leavePhoenixChannel(channel);
        reject(
          new PhoenixChannelTransportError("join_timeout", "Device events channel join timed out"),
        );
      });
  });
}

function createHandle(channel: Channel): DeviceEventChannelHandle {
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
