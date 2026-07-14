import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "../hybrid-encryption";
import { computeSigningKeyId } from "../signature";
import type { HybridSigningPublicKeyMaterial } from "../signature-types";
import type { CryptoWorkerClient } from "../worker/client";
import { blake3Base64Url } from "../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../jcs";
import {
  deviceActor,
  eventHash,
  eventHead,
  eventRef,
  identityActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
  signCheckpoint,
  signEvent,
} from "./primitives";
import type {
  InitialKeyDirectoryBootstrap,
  InitialKeyDirectoryInput,
  InitialUserKeyDirectoryBootstrap,
  InitialWorkspaceKeyDirectoryBootstrap,
} from "./types";

function initialEventActorAuthority(scopeKind: "user" | "workspace", scopeId: string) {
  return {
    key_scope_kind: scopeKind,
    key_scope_id: scopeId,
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        protocol: "refmd.initial-key-directory-authority",
        version: 1,
        scope_kind: scopeKind,
        scope_id: scopeId,
      }),
    ),
  };
}

export async function buildInitialKeyDirectoryBootstrap(
  input: InitialKeyDirectoryInput,
): Promise<InitialKeyDirectoryBootstrap> {
  const issuedAt = new Date().toISOString();
  const userBootstrap = await buildInitialUserKeyDirectoryBootstrap({
    userId: input.userId,
    deviceId: input.deviceId,
    identityHybridSigningPublicKeyMaterial: input.identityHybridSigningPublicKeyMaterial,
    identityHybridEncryptionPublicKeyMaterial: input.identityHybridEncryptionPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial: input.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: input.deviceHybridEncryptionPublicKeyMaterial,
    issuedAt,
  });
  const workspaceBootstrap = await buildInitialWorkspaceKeyDirectoryBootstrap({
    userId: input.userId,
    workspaceId: input.workspaceId,
    workspaceOwnerRoleId: input.workspaceOwnerRoleId,
    deviceId: input.deviceId,
    identityHybridSigningPublicKeyMaterial: input.identityHybridSigningPublicKeyMaterial,
    identityHybridEncryptionPublicKeyMaterial: input.identityHybridEncryptionPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial: input.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: input.deviceHybridEncryptionPublicKeyMaterial,
    issuedAt,
  });

  return {
    userEvents: userBootstrap.userEvents,
    userCheckpoint: userBootstrap.userCheckpoint,
    workspaceEvents: workspaceBootstrap.workspaceEvents,
    workspaceCheckpoint: workspaceBootstrap.workspaceCheckpoint,
  };
}

export async function buildInitialWorkspaceKeyDirectoryBootstrap(input: {
  userId: string;
  workspaceId: string;
  workspaceOwnerRoleId: string;
  deviceId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  issuedAt?: string;
}): Promise<InitialWorkspaceKeyDirectoryBootstrap> {
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const identitySigningKeyId = computeSigningKeyId(input.identityHybridSigningPublicKeyMaterial);
  const identityEncryptionKeyId = computeHybridEncryptionKeyId(
    input.identityHybridEncryptionPublicKeyMaterial,
  );
  const deviceSigningKeyId = computeSigningKeyId(input.deviceHybridSigningPublicKeyMaterial);
  const deviceEncryptionKeyId = computeHybridEncryptionKeyId(
    input.deviceHybridEncryptionPublicKeyMaterial,
  );

  const workspaceDeviceEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: 1,
    eventType: "device_key_added",
    actor: deviceActor(input.userId, input.deviceId, deviceSigningKeyId),
    body: {
      user_id: input.userId,
      device_id: input.deviceId,
      signing_key_id: deviceSigningKeyId,
      encryption_key_id: deviceEncryptionKeyId,
    },
  });
  const signedWorkspaceDeviceEvent = await signEvent("device", workspaceDeviceEvent);
  const workspaceDeviceRef = eventRef("workspace", input.workspaceId, workspaceDeviceEvent);

  const workspaceIdentitySigningEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: 2,
    eventType: "identity_key_added",
    actor: {
      ...deviceActor(input.userId, input.deviceId, deviceSigningKeyId),
      ...initialEventActorAuthority("workspace", input.workspaceId),
    },
    previousEventHash: eventHash(workspaceDeviceEvent),
    body: {
      key_id: identitySigningKeyId,
      key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          input.identityHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    },
  });
  const signedWorkspaceIdentitySigningEvent = await signEvent(
    "device",
    workspaceIdentitySigningEvent,
  );
  const workspaceIdentitySigningRef = eventRef(
    "workspace",
    input.workspaceId,
    workspaceIdentitySigningEvent,
  );

  const workspaceIdentityEncryptionEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: 3,
    eventType: "identity_key_added",
    actor: {
      ...deviceActor(input.userId, input.deviceId, deviceSigningKeyId),
      ...initialEventActorAuthority("workspace", input.workspaceId),
    },
    previousEventHash: eventHash(workspaceIdentitySigningEvent),
    body: {
      key_id: identityEncryptionKeyId,
      key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          input.identityHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    },
  });
  const signedWorkspaceIdentityEncryptionEvent = await signEvent(
    "device",
    workspaceIdentityEncryptionEvent,
  );
  const workspaceIdentityEncryptionRef = eventRef(
    "workspace",
    input.workspaceId,
    workspaceIdentityEncryptionEvent,
  );

  const workspaceMemberEvent = keyDirectoryEvent({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: 4,
    eventType: "member_added",
    actor: {
      ...deviceActor(input.userId, input.deviceId, deviceSigningKeyId),
      ...initialEventActorAuthority("workspace", input.workspaceId),
    },
    previousEventHash: eventHash(workspaceIdentityEncryptionEvent),
    body: {
      workspace_id: input.workspaceId,
      user_id: input.userId,
      role_id: input.workspaceOwnerRoleId,
      base_role: "owner",
    },
  });
  const signedWorkspaceMemberEvent = await signEvent("device", workspaceMemberEvent);

  const workspaceCheckpointPayload = keyDirectoryCheckpoint({
    scopeKind: "workspace",
    scopeId: input.workspaceId,
    sequence: 1,
    issuedAt,
    coveredEventHead: eventHead(workspaceMemberEvent),
    identityKeys: [
      keyEntry(
        identitySigningKeyId,
        input.identityHybridSigningPublicKeyMaterial,
        workspaceIdentitySigningRef,
      ),
      keyEntry(
        identityEncryptionKeyId,
        input.identityHybridEncryptionPublicKeyMaterial,
        workspaceIdentityEncryptionRef,
      ),
    ],
    deviceKeys: [
      keyEntry(deviceSigningKeyId, input.deviceHybridSigningPublicKeyMaterial, workspaceDeviceRef),
      keyEntry(
        deviceEncryptionKeyId,
        input.deviceHybridEncryptionPublicKeyMaterial,
        workspaceDeviceRef,
      ),
    ],
    shareParticipantKeys: [],
    revokedKeyIds: [],
  });
  const signedWorkspaceCheckpoint = await signCheckpoint(
    "device",
    "workspace_initial",
    workspaceCheckpointPayload,
  );

  return {
    workspaceEvents: [
      signedWorkspaceDeviceEvent,
      signedWorkspaceIdentitySigningEvent,
      signedWorkspaceIdentityEncryptionEvent,
      signedWorkspaceMemberEvent,
    ],
    workspaceCheckpoint: signedWorkspaceCheckpoint,
  };
}

export async function buildInitialUserKeyDirectoryBootstrap(input: {
  userId: string;
  deviceId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  issuedAt?: string;
  worker?: CryptoWorkerClient;
}): Promise<InitialUserKeyDirectoryBootstrap> {
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const identitySigningKeyId = computeSigningKeyId(input.identityHybridSigningPublicKeyMaterial);
  const identityEncryptionKeyId = computeHybridEncryptionKeyId(
    input.identityHybridEncryptionPublicKeyMaterial,
  );
  const deviceSigningKeyId = computeSigningKeyId(input.deviceHybridSigningPublicKeyMaterial);
  const deviceEncryptionKeyId = computeHybridEncryptionKeyId(
    input.deviceHybridEncryptionPublicKeyMaterial,
  );

  const userIdentityEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: 1,
    eventType: "identity_key_added",
    actor: identityActor(input.userId, identitySigningKeyId),
    body: {
      key_id: identitySigningKeyId,
      key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          input.identityHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    },
  });
  const signedUserIdentityEvent = await signEvent(
    "identity",
    userIdentityEvent,
    undefined,
    undefined,
    input.worker,
  );
  const userIdentityRef = eventRef("user", input.userId, userIdentityEvent);

  const userDeviceEvent = keyDirectoryEvent({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: 2,
    eventType: "device_key_added",
    actor: {
      ...identityActor(input.userId, identitySigningKeyId),
      ...initialEventActorAuthority("user", input.userId),
    },
    previousEventHash: eventHash(userIdentityEvent),
    body: {
      user_id: input.userId,
      device_id: input.deviceId,
      signing_key_id: deviceSigningKeyId,
      encryption_key_id: deviceEncryptionKeyId,
    },
  });
  const signedUserDeviceEvent = await signEvent(
    "identity",
    userDeviceEvent,
    undefined,
    undefined,
    input.worker,
  );
  const userDeviceRef = eventRef("user", input.userId, userDeviceEvent);

  const userCheckpointPayload = keyDirectoryCheckpoint({
    scopeKind: "user",
    scopeId: input.userId,
    sequence: 1,
    issuedAt,
    coveredEventHead: eventHead(userDeviceEvent),
    identityKeys: [
      keyEntry(identitySigningKeyId, input.identityHybridSigningPublicKeyMaterial, userIdentityRef),
      keyEntry(
        identityEncryptionKeyId,
        input.identityHybridEncryptionPublicKeyMaterial,
        userIdentityRef,
      ),
    ],
    deviceKeys: [
      keyEntry(deviceSigningKeyId, input.deviceHybridSigningPublicKeyMaterial, userDeviceRef),
      keyEntry(deviceEncryptionKeyId, input.deviceHybridEncryptionPublicKeyMaterial, userDeviceRef),
    ],
    shareParticipantKeys: [],
    revokedKeyIds: [],
  });
  const signedUserCheckpoint = await signCheckpoint(
    "identity",
    "identity_initial",
    userCheckpointPayload,
    undefined,
    undefined,
    input.worker,
  );

  return {
    userEvents: [signedUserIdentityEvent, signedUserDeviceEvent],
    userCheckpoint: signedUserCheckpoint,
  };
}
