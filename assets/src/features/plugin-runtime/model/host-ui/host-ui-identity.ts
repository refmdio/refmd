import type {
  PluginHostRpcContext,
  PluginHostRpcHandlerOwnerDescriptor,
} from "../../lib/host-rpc/host-rpc";

export function pluginContributionId(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  localId: string,
): string {
  return `plugin:${owner.applicationId}:${owner.activationId}:${localId}`;
}

export function ownerKey(owner: PluginHostRpcHandlerOwnerDescriptor): string {
  return [
    owner.pluginId,
    owner.packageId,
    owner.applicationId,
    owner.activationId,
    owner.ownerScopeKind,
    owner.workspaceId,
    owner.userId,
    owner.deviceId,
    owner.bundleHash,
    owner.manifestHash ?? "",
    owner.frameGeneration,
    owner.consentEpoch,
    owner.capabilityGrantId,
  ].join(":");
}

export function contributionKey(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  localId: string,
): string {
  return [ownerKey(owner), localId].join(":");
}

export function contextOwnerDescriptor(
  context: PluginHostRpcContext,
): PluginHostRpcHandlerOwnerDescriptor {
  return {
    pluginId: context.pluginId,
    packageId: context.packageId,
    applicationId: context.applicationId,
    activationId: context.activationId,
    ownerScopeKind: context.ownerScopeKind,
    workspaceId: context.workspaceId,
    userId: context.userId,
    deviceId: context.deviceId,
    bundleHash: context.bundleHash,
    manifestHash: context.manifestHash,
    frameGeneration: context.frameGeneration,
    consentEpoch: context.consentEpoch,
    capabilityGrantId: context.capabilityGrantId,
  };
}

export function sameOwner(
  first: PluginHostRpcHandlerOwnerDescriptor,
  second: PluginHostRpcHandlerOwnerDescriptor,
): boolean {
  return (
    first.pluginId === second.pluginId &&
    first.packageId === second.packageId &&
    first.applicationId === second.applicationId &&
    first.activationId === second.activationId &&
    first.ownerScopeKind === second.ownerScopeKind &&
    first.workspaceId === second.workspaceId &&
    first.userId === second.userId &&
    first.deviceId === second.deviceId &&
    first.bundleHash === second.bundleHash &&
    (first.manifestHash ?? "") === (second.manifestHash ?? "") &&
    first.frameGeneration === second.frameGeneration &&
    first.consentEpoch === second.consentEpoch &&
    first.capabilityGrantId === second.capabilityGrantId
  );
}
