import { deviceState } from "@/entities/session";
import { client, throwIfError, withUserPopParams } from "@/shared/api/core";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  createTrustedPluginRuntimeSignerKeyResolver,
  assertRuntimeBundleManifestAuthority,
  verifyRuntimeBundleProof,
} from "./runtime-proof";
import { loadPluginRuntimeLocalPins, saveVerifiedPluginRuntimePins } from "./runtime-pins";
import type {
  LoadedPluginRuntimeBundle,
  PluginRuntimeBundleEnvelope,
  PluginRuntimeBundleLoader,
  PluginRuntimeApplicationDescriptor,
  PluginSandboxDocumentSession,
  PluginSandboxDocumentSessionLoader,
  PluginSandboxDocumentSessionRequest,
  PluginRuntimeSignerKeyResolver,
} from "./runtime-types";

export const defaultPluginRuntimeBundleLoader: PluginRuntimeBundleLoader = async (
  descriptor: PluginRuntimeApplicationDescriptor,
): Promise<LoadedPluginRuntimeBundle> => {
  const localPins = await loadPluginRuntimeLocalPins(descriptor);
  const envelope = await createPluginSandboxDocumentEnvelope({
    workspaceId: descriptor.workspaceId,
    applicationId: descriptor.applicationId,
    stateHeadHash: localPins.state.latestEventHash,
    consentHeadHash: localPins.consent.latestEventHash,
    capabilityGrantId: descriptor.capabilityGrantId,
  });
  const session = sandboxDocumentSessionFromEnvelope(envelope, descriptor.capabilityGrantId);
  await verifyRuntimeBundleProof(
    descriptor,
    envelope,
    localPins,
    createDefaultPluginRuntimeSignerKeyResolver(),
  );
  const { authority } = assertRuntimeBundleManifestAuthority(envelope);
  await saveVerifiedPluginRuntimePins(descriptor, envelope);

  return {
    pluginId: envelope.plugin_id,
    packageId: envelope.package_id,
    applicationId: envelope.application_id,
    activationId: envelope.activation_id,
    ownerScopeKind: descriptor.ownerScopeKind,
    workspaceId: envelope.workspace_id,
    userId: descriptor.userId,
    deviceId: descriptor.deviceId,
    bundleHash: envelope.bundle_hash,
    manifestHash: envelope.manifest_hash,
    consentEpoch: envelope.consent_epoch,
    sandboxDocumentUrl: session.sandboxDocumentUrl,
    bootNonce: session.bootNonce,
    frameGeneration: session.frameGeneration,
    frameScope: session.frameScope,
    permissions: authority.permissions,
    documentScope: authority.documentScope,
    networkEndpoints: authority.networkEndpoints,
    rendererSlots: authority.rendererSlots,
    highRiskConsents: authority.highRiskConsents,
  };
};

export const defaultPluginSandboxDocumentSessionLoader: PluginSandboxDocumentSessionLoader = async (
  request,
) =>
  sandboxDocumentSessionFromEnvelope(
    await createPluginSandboxDocumentEnvelope(request),
    request.capabilityGrantId,
  );

async function createPluginSandboxDocumentEnvelope(
  request: PluginSandboxDocumentSessionRequest,
): Promise<PluginRuntimeBundleEnvelope> {
  return runtimeBundleEnvelope(
    throwIfError(
      await client.POST(
        "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/sandbox-documents",
        {
          params: withUserPopParams({
            path: {
              workspace_id: request.workspaceId,
              application_id: request.applicationId,
            },
          }),
          body: {
            state_head_hash: request.stateHeadHash,
            consent_head_hash: request.consentHeadHash,
            capability_grant_id: request.capabilityGrantId,
            ...(request.frameScope ? { frame_scope: request.frameScope } : {}),
            ...(request.wasmBrowserTarget
              ? { wasm_browser_target: request.wasmBrowserTarget }
              : {}),
          },
        },
      ),
    ),
  );
}

function sandboxDocumentSessionFromEnvelope(
  envelope: PluginRuntimeBundleEnvelope,
  expectedCapabilityGrantId: string,
): PluginSandboxDocumentSession {
  if (envelope.capability_grant_id !== expectedCapabilityGrantId) {
    throw new Error("capability_grant_id_invalid");
  }
  return {
    sandboxDocumentUrl: assertSandboxDocumentUrl(envelope.sandbox_document_url),
    bootNonce: assertOpaqueRuntimeToken(envelope.boot_nonce, "boot_nonce"),
    frameGeneration: assertPositiveInteger(envelope.frame_generation, "frame_generation"),
    frameScope: envelope.frame_scope === "secondary" ? "secondary" : "primary",
    capabilityGrantId: envelope.capability_grant_id,
  };
}

function runtimeBundleEnvelope(value: unknown): PluginRuntimeBundleEnvelope {
  return value as PluginRuntimeBundleEnvelope;
}

export function createDefaultPluginRuntimeSignerKeyResolver(): PluginRuntimeSignerKeyResolver {
  const keyDirectories = new Map<string, Promise<Record<string, unknown>>>();
  return createTrustedPluginRuntimeSignerKeyResolver(async (proof, purpose) => {
    const scope = signerKeyScope(proof, purpose);
    const cacheKey = `${scope.scopeKind}:${scope.scopeId}`;
    let keyDirectory = keyDirectories.get(cacheKey);
    if (!keyDirectory) {
      const device = deviceState();
      if (!device?.deviceId) throw new Error("trusted_signer_device_required");
      keyDirectory = fetchVerifiedKeyDirectory({
        scopeKind: scope.scopeKind,
        scopeId: scope.scopeId,
        popDeviceId: device.deviceId,
      }).then(({ checkpoint }) => checkpoint.payload as Record<string, unknown>);
      keyDirectories.set(cacheKey, keyDirectory);
    }
    return keyDirectory;
  });
}

function signerKeyScope(
  proof: Parameters<PluginRuntimeSignerKeyResolver>[0],
  purpose: Parameters<PluginRuntimeSignerKeyResolver>[1],
): { scopeKind: "user" | "workspace"; scopeId: string } {
  if (purpose === "approval") {
    const subject = requireRecord(proof.subject, "approval_subject_invalid");
    const ownerScopeKind = stringField(subject.owner_scope_kind, "approval_owner_scope_invalid");
    if (ownerScopeKind === "user") {
      return {
        scopeKind: "user",
        scopeId: stringField(subject.owner_user_id, "approval_owner_user_required"),
      };
    }
    if (ownerScopeKind === "workspace") {
      return {
        scopeKind: "workspace",
        scopeId: stringField(subject.owner_workspace_id, "approval_owner_workspace_required"),
      };
    }
    throw new Error("approval_owner_scope_invalid");
  }

  const actor = requireRecord(proof.actor, "runtime_proof_actor_invalid");
  const actorScopeKind = stringField(actor.key_scope_kind, "runtime_proof_actor_scope_invalid");
  const actorScopeId = stringField(actor.key_scope_id, "runtime_proof_actor_scope_invalid");
  if (actorScopeKind === "workspace") return { scopeKind: "workspace", scopeId: actorScopeId };
  if (actorScopeKind === "user") return { scopeKind: "user", scopeId: actorScopeId };
  throw new Error("runtime_proof_actor_scope_invalid");
}

function requireRecord(value: StrictJsonValue, error: string): Record<string, StrictJsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(error);
  return value as Record<string, StrictJsonValue>;
}

function stringField(value: StrictJsonValue | undefined, error: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(error);
  return value;
}

function assertSandboxDocumentUrl(value: string | undefined): string {
  if (!value?.startsWith("/api/plugin-runtime/sandbox-documents/")) {
    throw new Error("sandbox_document_url_invalid");
  }
  return value;
}

function assertOpaqueRuntimeToken(value: string | undefined, field: string): string {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${field}_invalid`);
  return value;
}

function assertPositiveInteger(value: number | undefined, field: string): number {
  if (value === undefined || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${field}_invalid`);
  }
  return value;
}
