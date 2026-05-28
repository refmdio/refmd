import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type {
  HybridSignature,
  HybridSigningPublicKeyMaterial,
} from "@/shared/lib/crypto/signature";
import type { PluginConsentPin, PluginStatePin } from "@/shared/lib/crypto/trust-store";
import type {
  PluginDocumentScope,
  PluginHighRiskConsent,
  PluginPermission,
} from "../capability/capability-enforcement";
import type { PluginNetworkEndpointPolicy } from "../network/host-network";
import type { PluginRendererSlot } from "../renderer/host-renderer";
import type { PluginSandboxBundleArtifact } from "../sandbox/sandbox-runtime";

export interface PluginRuntimeApplicationDescriptor {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  applicationScopeKind?: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  stateHeadHash: string;
  consentHeadHash: string;
  consentEpoch?: number;
  version?: string;
  bundleHash?: string;
  manifestHash?: string;
  resourceManifestHash?: string;
  permissionsHash?: string;
  endpointHash?: string;
  rendererSlotsHash?: string;
  documentScopeHash?: string;
  approvalEventHash?: string;
  signerDeviceId?: string;
  signerUserId?: string;
  author?: string;
  title?: string;
  capabilityGrantId: string;
  permissions?: readonly PluginPermission[];
  documentScope?: PluginDocumentScope;
  networkEndpoints?: readonly PluginNetworkEndpointPolicy[];
  rendererSlots?: readonly PluginRendererSlot[];
  highRiskConsents?: readonly PluginHighRiskConsent[];
}

export interface LoadedPluginRuntimeBundle {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  bundleHash: string;
  manifestHash: string;
  consentEpoch: number;
  sandboxDocumentUrl: string;
  bootNonce: string;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  bundle?: PluginSandboxBundleArtifact;
  permissions: readonly PluginPermission[];
  documentScope?: PluginDocumentScope;
  networkEndpoints: readonly PluginNetworkEndpointPolicy[];
  rendererSlots: readonly PluginRendererSlot[];
  highRiskConsents: readonly PluginHighRiskConsent[];
}

export type PluginRuntimeBundleLoader = (
  descriptor: PluginRuntimeApplicationDescriptor,
) => Promise<LoadedPluginRuntimeBundle>;

export interface PluginSandboxDocumentSessionRequest {
  workspaceId: string;
  applicationId: string;
  stateHeadHash: string;
  consentHeadHash: string;
  capabilityGrantId: string;
  frameScope?: "primary" | "secondary";
  wasmBrowserTarget?: string;
}

export interface PluginSandboxDocumentSession {
  sandboxDocumentUrl: string;
  bootNonce: string;
  frameGeneration: number;
  frameScope: "primary" | "secondary";
  capabilityGrantId: string;
}

export type PluginSandboxDocumentSessionLoader = (
  request: PluginSandboxDocumentSessionRequest,
) => Promise<PluginSandboxDocumentSession>;

export interface PluginRuntimeBundleEnvelope {
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  owner_scope_kind: string;
  workspace_id: string;
  state_head_hash: string;
  bundle_hash: string;
  manifest_hash: string;
  main_js_hash: string;
  styles_css_hash: string;
  resource_manifest_hash: string;
  resource_manifest: readonly PluginRuntimeResourceManifestEntryEnvelope[];
  permissions_hash: string;
  endpoint_hash: string;
  renderer_slots_hash: string;
  document_scope_hash: string;
  approval_event_hash: string;
  consent_event_hash: string;
  consent_epoch: number;
  approval_proof: PluginRuntimeSignatureProofEnvelope;
  consent_proof: PluginRuntimeSignatureProofEnvelope;
  manifest_json_bytes: string;
  main_js?: string;
  styles_css?: string;
  resources?: readonly PluginRuntimeResourceEnvelope[];
  sandbox_document_url?: string;
  boot_nonce?: string;
  frame_generation?: number;
  frame_scope?: "primary" | "secondary";
  capability_grant_id?: string;
  expires_at_ms?: number;
}

export interface PluginRuntimeResourceManifestEntryEnvelope {
  path: string;
  kind: string;
  media_type: string;
  byte_length: number;
  hash: string;
  executable: boolean;
}

export interface PluginRuntimeResourceEnvelope {
  path: string;
  kind: string;
  media_type: string;
  byte_length: number;
  hash: string;
  bytes: string;
}

export interface PluginRuntimeSignatureProofEnvelope {
  event_hash: string;
  subject: StrictJsonValue;
  actor: StrictJsonValue;
  hybrid_signature: HybridSignature;
  signing_key_id: string;
  approval_authority?: StrictJsonValue;
  approval_authority_checkpoint?: StrictJsonValue;
  approval_authority_event_ancestry?: StrictJsonValue[];
}

export interface PluginRuntimeLocalPins {
  state: PluginStatePin;
  consent: PluginConsentPin;
}

export type PluginRuntimeSignerKeyResolver = (
  proof: PluginRuntimeSignatureProofEnvelope,
  purpose: "approval" | "consent",
  envelope: PluginRuntimeBundleEnvelope,
) => Promise<HybridSigningPublicKeyMaterial | null>;

export interface PluginRuntimePinWriter {
  saveState(pin: PluginStatePin): Promise<void>;
  saveConsent(pin: PluginConsentPin): Promise<void>;
}

export interface PluginRuntimeApprovalAuthorityVerification {
  descriptor: PluginRuntimeApplicationDescriptor;
  proof: PluginRuntimeSignatureProofEnvelope;
  approvalSubject: Record<string, StrictJsonValue>;
  authority: Record<string, StrictJsonValue>;
}

export type PluginRuntimeApprovalAuthorityVerifier = (
  params: PluginRuntimeApprovalAuthorityVerification,
) => Promise<void> | void;
