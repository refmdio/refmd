import { createEffect, createMemo, createSignal, For, Show, type JSX } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import {
  CheckIcon,
  KeyIcon,
  LinkIcon,
  PackagePlusIcon,
  PowerIcon,
  RefreshCwIcon,
  Trash2Icon,
  UploadIcon,
  XIcon,
} from "lucide-solid";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { currentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import {
  arrayBufferToBase64,
  pluginsApi,
  type PluginActivationInfo,
  type PluginApplicationInfo,
  type PluginApprovalPayload,
  type PluginBundleCandidateInfo,
  type PluginOwnerScopeKind,
  type PluginPackageInfo,
} from "@/shared/api";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { HybridSignature } from "@/shared/lib/crypto/signature";
import {
  getPluginStatePin,
  savePluginConsentPin,
  savePluginStatePin,
  type PluginStatePin,
} from "@/shared/lib/crypto/trust-store";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

type SourceKind = "remote_https_url" | "local_upload";

export interface PluginActivationLocalDataTarget {
  workspaceId: string;
  applicationId: string;
  packageId: string;
  activationId: string;
  userId: string;
  deviceId: string;
}

interface PluginRuntimeApplicationDescriptor {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  applicationScopeKind?: string;
  workspaceId: string;
  userId?: string;
  deviceId?: string;
  stateHeadHash: string;
  approvalEventHash?: string | null;
  consentHeadHash?: string | null;
  consentEpoch?: number | null;
  version?: string | null;
  bundleHash?: string | null;
  manifestHash?: string | null;
  resourceManifestHash?: string | null;
  permissionsHash?: string | null;
  endpointHash?: string | null;
  rendererSlotsHash?: string | null;
  documentScopeHash?: string | null;
  signerDeviceId?: string | null;
  signerUserId?: string | null;
  capabilityGrantId?: string | null;
  documentScope?: unknown;
  title?: string | null;
  author?: string | null;
  permissions?: readonly string[];
  networkEndpoints?: readonly unknown[];
  highRiskConsents?: readonly string[];
}

interface PluginConsentRequiredDescriptor extends PluginRuntimeApplicationDescriptor {
  applicationScopeKind: string;
  approvalEventHash: string;
  consentHeadHash: string | null;
  consentEpoch: number | null;
  version: string;
  bundleHash: string;
  manifestHash: string;
  resourceManifestHash: string;
  permissionsHash: string;
  endpointHash: string;
  rendererSlotsHash: string;
  documentScopeHash: string;
  signerDeviceId: string;
  signerUserId: string;
  documentScope: Record<string, unknown> | null;
  title: string;
  author: string;
  permissions: readonly string[];
  networkEndpoints: readonly Record<string, unknown>[];
  highRiskConsents: readonly string[];
}

interface PluginConsentSubject extends Record<string, StrictJsonValue> {
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  owner_scope_kind: string;
  application_scope_kind: string;
  version: string;
  bundle_hash: string;
  manifest_hash: string;
  resource_manifest_hash: string;
  permissions_hash: string;
  endpoint_hash: string;
  document_scope_hash: string;
  signer_device_id: string;
  signer_user_id: string;
  user_id: string;
  device_id: string;
  workspace_id: string;
  consent_epoch: number;
  previous_event_hash: string;
  decision: "allow" | "deny" | "revoke";
}

interface PluginConsentEventResponse {
  consent_event?: {
    event_hash?: string;
    decision?: string;
    consent_epoch?: number;
  };
}

interface PluginCredentialEndpointInfo {
  id: string;
  url: string;
  methods: readonly string[];
  credentialAudience: string;
}

export interface CommunityPluginsSectionProps {
  purgeLocalData: (target: PluginActivationLocalDataTarget) => Promise<void>;
  listRuntimeApplications: (
    workspaceId: string,
  ) => Promise<readonly PluginRuntimeApplicationDescriptor[]>;
  requestRuntimeApplicationsRefresh: (workspaceId?: string | null) => void;
  beginRuntimeApplicationRevocation?: (applicationId: string) => void;
  closeRuntimeByApplication?: (applicationId: string, reason?: string) => void | Promise<void>;
  releaseRuntimeApplicationRevocation?: (applicationId: string) => void;
  storeCredential: (registration: {
    credentialId: string;
    pluginId: string;
    workspaceId: string;
    packageId: string;
    applicationId: string;
    activationId: string;
    userId: string;
    deviceId: string;
    audience: string;
    endpoint: string;
    method: string;
    headers: Record<string, string>;
  }) => Promise<void>;
  submitConsentDecision: (
    descriptor: PluginConsentRequiredDescriptor,
    decision: "allow" | "deny" | "revoke",
    options: {
      userId: string;
      deviceId: string;
      sign: (consent: PluginConsentSubject) => Promise<{ signature: HybridSignature }>;
      appendConsent: (body: Record<string, StrictJsonValue>) => Promise<PluginConsentEventResponse>;
      getStatePin: typeof getPluginStatePin;
      saveConsentPin: typeof savePluginConsentPin;
      nowMs: () => number;
    },
  ) => Promise<void>;
}

function packageLabel(packageInfo: PluginPackageInfo): string {
  return `${packageInfo.plugin_id || "Unknown plugin"} ${packageInfo.version || ""}`.trim();
}

function scopeLabel(scope: PluginOwnerScopeKind): string {
  return scope === "user" ? "Personal" : "Workspace";
}

export function scopeChoiceLabel(scope: PluginOwnerScopeKind): string {
  return scope === "user" ? "Use for myself" : "Share with workspace";
}

function sourceScopeSummary(candidate: PluginBundleCandidateInfo): readonly PluginOwnerScopeKind[] {
  const scopes = candidate.scope_summary?.supported_owner_scopes ?? [];
  return scopes.filter(
    (scope): scope is PluginOwnerScopeKind => scope === "user" || scope === "workspace",
  );
}

function strictRecord(value: unknown, error: string): Record<string, StrictJsonValue> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(error);
  return value as Record<string, StrictJsonValue>;
}

function objectRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return { ...(value as Record<string, unknown>) };
}

function requiredRuntimeString(
  runtime: PluginRuntimeApplicationDescriptor,
  key: keyof PluginRuntimeApplicationDescriptor,
): string {
  const value = runtime[key];
  if (typeof value !== "string" || !value) throw new Error(`plugin_runtime_${String(key)}_missing`);
  return value;
}

function consentDescriptorFromRuntime(
  runtime: PluginRuntimeApplicationDescriptor,
): PluginConsentRequiredDescriptor {
  return {
    pluginId: runtime.pluginId,
    packageId: runtime.packageId,
    applicationId: runtime.applicationId,
    activationId: runtime.activationId,
    ownerScopeKind: runtime.ownerScopeKind,
    applicationScopeKind: runtime.applicationScopeKind ?? "workspace",
    workspaceId: runtime.workspaceId,
    stateHeadHash: runtime.stateHeadHash,
    approvalEventHash: requiredRuntimeString(runtime, "approvalEventHash"),
    consentHeadHash: runtime.consentHeadHash ?? null,
    consentEpoch: typeof runtime.consentEpoch === "number" ? runtime.consentEpoch : null,
    version: requiredRuntimeString(runtime, "version"),
    bundleHash: requiredRuntimeString(runtime, "bundleHash"),
    manifestHash: requiredRuntimeString(runtime, "manifestHash"),
    resourceManifestHash: requiredRuntimeString(runtime, "resourceManifestHash"),
    permissionsHash: requiredRuntimeString(runtime, "permissionsHash"),
    endpointHash: requiredRuntimeString(runtime, "endpointHash"),
    rendererSlotsHash: requiredRuntimeString(runtime, "rendererSlotsHash"),
    documentScopeHash: requiredRuntimeString(runtime, "documentScopeHash"),
    signerDeviceId: requiredRuntimeString(runtime, "signerDeviceId"),
    signerUserId: requiredRuntimeString(runtime, "signerUserId"),
    documentScope: runtime.documentScope ? objectRecord(runtime.documentScope) : null,
    title: runtime.title ?? runtime.pluginId,
    author: runtime.author ?? "",
    permissions: runtime.permissions ?? [],
    networkEndpoints: (runtime.networkEndpoints ?? []).map(objectRecord),
    highRiskConsents: runtime.highRiskConsents ?? [],
  };
}

function capabilityLabel(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function CapabilityList(props: { label: string; values: readonly unknown[] }) {
  return (
    <div class="space-y-1">
      <p class="text-xs font-medium text-foreground">{props.label}</p>
      <Show
        when={props.values.length > 0}
        fallback={<p class="text-xs text-muted-foreground">None</p>}
      >
        <ul class="max-h-28 space-y-1 overflow-auto border border-border/60 bg-background/60 p-2">
          <For each={props.values}>
            {(value) => (
              <li class="break-all font-mono text-[11px] text-muted-foreground">
                {capabilityLabel(value)}
              </li>
            )}
          </For>
        </ul>
      </Show>
    </div>
  );
}

function policyLabel(application: PluginApplicationInfo): string {
  switch (application.workspace_policy_result) {
    case "allowed":
      return "Allowed";
    case "denied":
      return "Denied";
    case "needs_admin_review":
      return "Needs admin review";
    default:
      return application.workspace_policy_result;
  }
}

function ListEmpty(props: { children: string }) {
  return <p class="py-6 text-center text-sm text-muted-foreground">{props.children}</p>;
}

function requiredPluginField(value: string | null | undefined, error: string): string {
  if (!value) throw new Error(error);
  return value;
}

export async function saveRuntimeDescriptorPluginStatePin(
  runtime: PluginRuntimeApplicationDescriptor,
  nowMs: number = Date.now(),
  saveStatePin: (pin: PluginStatePin) => Promise<void> = savePluginStatePin,
): Promise<void> {
  await saveStatePin({
    workspaceId: runtime.workspaceId,
    packageId: runtime.packageId,
    applicationId: runtime.applicationId,
    activationId: runtime.activationId,
    latestEventHash: runtime.stateHeadHash,
    bundleHash: requiredRuntimeString(runtime, "bundleHash"),
    approvalEventHash: requiredRuntimeString(runtime, "approvalEventHash"),
    updatedAtMs: nowMs,
  });
}

export async function saveApplicationActivationPluginStatePin(
  application: PluginApplicationInfo,
  activation: PluginActivationInfo,
  nowMs: number = Date.now(),
  saveStatePin: (pin: PluginStatePin) => Promise<void> = savePluginStatePin,
): Promise<void> {
  const stateHead = requiredPluginField(
    application.state_head_hash,
    "plugin_application_state_missing",
  );
  await saveStatePin({
    workspaceId: application.workspace_id,
    packageId: application.package_id,
    applicationId: application.id,
    activationId: activation.id,
    latestEventHash: stateHead,
    bundleHash: requiredPluginField(
      activation.bundle_hash,
      "plugin_activation_bundle_hash_missing",
    ),
    approvalEventHash: stateHead,
    updatedAtMs: nowMs,
  });
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function stringList(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function credentialEndpoints(
  application: PluginApplicationInfo,
): readonly PluginCredentialEndpointInfo[] {
  const endpoints = Array.isArray(application.network_endpoints)
    ? application.network_endpoints
    : [];
  return endpoints.flatMap((entry) => {
    const id = stringValue((entry as Record<string, unknown>).id);
    const url = stringValue((entry as Record<string, unknown>).url);
    const credentialAudience = stringValue((entry as Record<string, unknown>).credentialAudience);
    if (!id || !url || !credentialAudience) return [];
    const methods = stringList((entry as Record<string, unknown>).methods).map((method) =>
      method.toUpperCase(),
    );
    return [
      {
        id,
        url,
        credentialAudience,
        methods: methods.length > 0 ? methods : ["GET"],
      },
    ];
  });
}

export function canApplyPluginPackage(
  packageInfo: PluginPackageInfo,
  workspaceRole?: string | null,
): boolean {
  if (!packageInfo.current_bundle_id) return false;
  if (packageInfo.owner_scope_kind !== "workspace") return true;
  return workspaceRole === "owner" || workspaceRole === "admin";
}

export function canManagePluginApplicationPolicy(
  application: PluginApplicationInfo,
  workspaceRole: string | null | undefined,
): boolean {
  return !application.deleted_at && (workspaceRole === "owner" || workspaceRole === "admin");
}

export async function runWithPluginRuntimeApplicationRevocation<T>(
  applicationId: string,
  callbacks: {
    beginRuntimeApplicationRevocation?: (applicationId: string) => void;
    releaseRuntimeApplicationRevocation?: (applicationId: string) => void;
  },
  run: () => Promise<T>,
): Promise<T> {
  callbacks.beginRuntimeApplicationRevocation?.(applicationId);
  try {
    return await run();
  } finally {
    callbacks.releaseRuntimeApplicationRevocation?.(applicationId);
  }
}

export function upsertPluginApplication(
  applications: readonly PluginApplicationInfo[] | undefined,
  updated: PluginApplicationInfo,
): readonly PluginApplicationInfo[] {
  const current = applications ?? [];
  if (current.some((application) => application.id === updated.id)) {
    return current.map((application) => (application.id === updated.id ? updated : application));
  }
  return [updated, ...current];
}

export function upsertPluginActivation(
  activations: readonly PluginActivationInfo[] | undefined,
  updated: PluginActivationInfo,
): readonly PluginActivationInfo[] {
  const current = activations ?? [];
  if (current.some((activation) => activation.id === updated.id)) {
    return current.map((activation) => (activation.id === updated.id ? updated : activation));
  }
  return [updated, ...current];
}

export function upsertPluginPackage(
  packages: readonly PluginPackageInfo[] | undefined,
  updated: PluginPackageInfo,
): readonly PluginPackageInfo[] {
  const current = packages ?? [];
  if (current.some((packageInfo) => packageInfo.id === updated.id)) {
    return current.map((packageInfo) => (packageInfo.id === updated.id ? updated : packageInfo));
  }
  return [updated, ...current];
}

export async function saveAppliedPluginStatePin(
  packageInfo: PluginPackageInfo,
  application: PluginApplicationInfo,
  activation: PluginActivationInfo | undefined,
  nowMs: number = Date.now(),
  saveStatePin: (pin: PluginStatePin) => Promise<void> = savePluginStatePin,
): Promise<void> {
  if (!activation) throw new Error("plugin_activation_missing");
  if (application.package_id !== packageInfo.id) throw new Error("plugin_package_mismatch");

  const packageStateHead = requiredPluginField(
    packageInfo.state_head_hash,
    "plugin_package_state_missing",
  );
  const applicationStateHead = requiredPluginField(
    application.state_head_hash,
    "plugin_application_state_missing",
  );

  await saveStatePin({
    workspaceId: application.workspace_id,
    packageId: packageInfo.id,
    applicationId: application.id,
    activationId: activation.id,
    latestEventHash: applicationStateHead,
    bundleHash: requiredPluginField(
      activation.bundle_hash ?? packageInfo.bundle_hash,
      "plugin_bundle_hash_missing",
    ),
    approvalEventHash: packageStateHead,
    updatedAtMs: nowMs,
  });
}

export async function savePromotedPluginStatePin(
  promotion: {
    package: PluginPackageInfo;
    application?: PluginApplicationInfo;
    activation?: PluginActivationInfo;
  },
  nowMs: number = Date.now(),
  saveStatePin: (pin: PluginStatePin) => Promise<void> = savePluginStatePin,
): Promise<void> {
  if (!promotion.application) return;
  await saveAppliedPluginStatePin(
    promotion.package,
    promotion.application,
    promotion.activation,
    nowMs,
    saveStatePin,
  );
}

export async function purgeDeletedActivationLocalData(
  activation: PluginActivationInfo,
  application: PluginApplicationInfo | undefined,
  deviceId: string | null | undefined,
  purgeLocalData: (target: PluginActivationLocalDataTarget) => Promise<void>,
): Promise<void> {
  const workspaceId = activation.workspace_id ?? application?.workspace_id;
  const packageId = activation.package_id ?? application?.package_id;
  const userId = activation.user_id;

  if (!workspaceId || !packageId || !userId || !deviceId) {
    throw new Error("plugin_activation_cleanup_context_missing");
  }

  await purgeLocalData({
    workspaceId,
    packageId,
    applicationId: activation.application_id,
    activationId: activation.id,
    userId,
    deviceId,
  });
}

export async function purgeDeletedApplicationLocalData(
  application: PluginApplicationInfo,
  activations: readonly PluginActivationInfo[],
  deviceId: string | null | undefined,
  purgeLocalData: (target: PluginActivationLocalDataTarget) => Promise<void>,
): Promise<void> {
  const applicationActivations = activations.filter(
    (activation) => activation.application_id === application.id && !activation.deleted_at,
  );

  for (const activation of applicationActivations) {
    const targetDeviceId = activation.device_id ?? deviceId;
    if (
      !application.workspace_id ||
      !application.package_id ||
      !activation.user_id ||
      !targetDeviceId
    ) {
      throw new Error("plugin_application_cleanup_context_missing");
    }

    await purgeLocalData({
      workspaceId: application.workspace_id,
      packageId: application.package_id,
      applicationId: application.id,
      activationId: activation.id,
      userId: activation.user_id,
      deviceId: targetDeviceId,
    });
  }
}

function ScopeButton(props: {
  selected: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: JSX.Element;
}) {
  return (
    <Button
      type="button"
      variant={props.selected ? "default" : "outline"}
      size="sm"
      disabled={props.disabled}
      onClick={props.onClick}
      aria-pressed={props.selected}
    >
      {props.children}
    </Button>
  );
}

function PluginReviewSummary(props: { candidate: PluginBundleCandidateInfo }) {
  const summary = () => props.candidate.capability_summary ?? {};
  const scopeSummary = () => sourceScopeSummary(props.candidate);
  const permissions = () => summary().permissions ?? [];
  const endpoints = () => summary().network_endpoints ?? [];
  const rendererSlots = () => summary().renderer_slots ?? [];
  const documentScopes = () => summary().document_scopes ?? [];

  return (
    <div class="space-y-3 border border-border/60 bg-muted/20 p-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0">
          <p class="text-xs text-muted-foreground">
            {scopeLabel(props.candidate.owner_scope_kind)}
          </p>
          <h4 class="truncate text-sm font-medium">
            {props.candidate.plugin_id || "Unknown plugin"}
          </h4>
          <p class="text-xs text-muted-foreground">
            Version {props.candidate.version || "unknown"}
          </p>
        </div>
        <span class="border border-border/60 px-2 py-1 text-[10px] uppercase tracking-[0.24em] text-muted-foreground">
          {props.candidate.validation_status || "pending"}
        </span>
      </div>

      <div class="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
        <div>Bundle: {props.candidate.bundle_hash || "unavailable"}</div>
        <div>Manifest: {props.candidate.manifest_hash || "unavailable"}</div>
        <div>
          Approval proof: {props.candidate.approval_summary?.approval_event_hash || "unavailable"}
        </div>
        <div>
          Previous approval proof:{" "}
          {props.candidate.approval_summary?.previous_approval_event_hash || "unavailable"}
        </div>
        <div>
          Manifest scopes:{" "}
          {scopeSummary().length > 0 ? scopeSummary().map(scopeLabel).join(", ") : "unavailable"}
        </div>
        <div>
          Workspace use: {props.candidate.scope_summary?.workspace_application || "unknown"}
        </div>
      </div>

      <div class="grid gap-3 sm:grid-cols-2">
        <CapabilityList label="Permissions" values={permissions()} />
        <CapabilityList label="Network endpoints" values={endpoints()} />
        <CapabilityList label="Renderer slots" values={rendererSlots()} />
        <CapabilityList label="Document scopes" values={documentScopes()} />
      </div>

      <Show
        when={
          Array.isArray(props.candidate.validation_errors) &&
          props.candidate.validation_errors.length > 0
        }
      >
        <pre class="max-h-32 overflow-auto border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
          {JSON.stringify(props.candidate.validation_errors, null, 2)}
        </pre>
      </Show>
    </div>
  );
}

function PluginApplicationRow(props: {
  application: PluginApplicationInfo;
  activation?: PluginActivationInfo;
  busy: boolean;
  canManagePolicy: boolean;
  onSaveCredential: (
    application: PluginApplicationInfo,
    activation: PluginActivationInfo,
    endpoint: PluginCredentialEndpointInfo,
    credentialId: string,
    headerName: string,
    headerValue: string,
    method: string,
  ) => Promise<void>;
  onSetPolicy: (
    application: PluginApplicationInfo,
    workspacePolicyResult: "allowed" | "denied",
  ) => void;
  onToggle: (application: PluginApplicationInfo) => void;
  canRevokeConsent: boolean;
  onRevokeConsent: (application: PluginApplicationInfo) => void;
  onDelete: (application: PluginApplicationInfo) => void;
}) {
  const endpoints = createMemo(() => credentialEndpoints(props.application));
  const [selectedEndpointId, setSelectedEndpointId] = createSignal("");
  const [credentialId, setCredentialId] = createSignal("api-key");
  const [headerName, setHeaderName] = createSignal("authorization");
  const [headerValue, setHeaderValue] = createSignal("");
  const [method, setMethod] = createSignal("");

  createEffect(() => {
    const first = endpoints()[0];
    if (!first) return;
    if (
      !selectedEndpointId() ||
      !endpoints().some((endpoint) => endpoint.id === selectedEndpointId())
    ) {
      setSelectedEndpointId(first.id);
      setMethod(first.methods[0] ?? "GET");
    }
  });

  const selectedEndpoint = () =>
    endpoints().find((endpoint) => endpoint.id === selectedEndpointId()) ?? endpoints()[0] ?? null;

  const saveCredential = () => {
    const endpoint = selectedEndpoint();
    const activation = props.activation;
    if (!endpoint || !activation) return;
    void props.onSaveCredential(
      props.application,
      activation,
      endpoint,
      credentialId(),
      headerName(),
      headerValue(),
      method() || endpoint.methods[0] || "GET",
    );
  };

  return (
    <div class="border-b border-border/60 py-3 last:border-0">
      <div class="flex items-center justify-between gap-3">
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <h4 class="truncate text-sm font-medium">{props.application.plugin_id}</h4>
            <span class="border border-border/60 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
              {policyLabel(props.application)}
            </span>
            <span class="text-xs text-muted-foreground">
              {props.application.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <p class="mt-1 truncate text-xs text-muted-foreground">
            {props.application.application_mode} / {props.application.package_id}
          </p>
        </div>
        <div class="flex shrink-0 items-center gap-1">
          <Show
            when={props.canManagePolicy && props.application.workspace_policy_result !== "allowed"}
          >
            <Button
              size="icon-sm"
              variant="ghost"
              title="Allow plugin"
              disabled={props.busy}
              onClick={() => props.onSetPolicy(props.application, "allowed")}
            >
              <CheckIcon class="size-3.5" />
            </Button>
          </Show>
          <Show
            when={props.canManagePolicy && props.application.workspace_policy_result !== "denied"}
          >
            <Button
              size="icon-sm"
              variant="ghost"
              title="Deny plugin"
              disabled={props.busy}
              onClick={() => props.onSetPolicy(props.application, "denied")}
            >
              <XIcon class="size-3.5" />
            </Button>
          </Show>
          <Button
            size="icon-sm"
            variant="ghost"
            title={props.application.enabled ? "Disable" : "Enable"}
            disabled={props.busy}
            onClick={() => props.onToggle(props.application)}
          >
            <PowerIcon class="size-3.5" />
          </Button>
          <Show when={props.canRevokeConsent}>
            <Button
              size="icon-sm"
              variant="ghost"
              title="Revoke consent"
              disabled={props.busy}
              onClick={() => props.onRevokeConsent(props.application)}
            >
              <XIcon class="size-3.5" />
            </Button>
          </Show>
          <Button
            size="icon-sm"
            variant="ghost"
            title="Remove"
            disabled={props.busy}
            onClick={() => props.onDelete(props.application)}
          >
            <Trash2Icon class="size-3.5" />
          </Button>
        </div>
      </div>
      <Show when={endpoints().length > 0}>
        <div class="mt-3 border border-border/60 bg-background/60 p-3">
          <div class="mb-2 flex items-center gap-2 text-xs font-medium">
            <KeyIcon class="size-3.5" />
            Plugin credentials
          </div>
          <div class="grid gap-2 md:grid-cols-2">
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">Endpoint</span>
              <select
                class="h-8 w-full border border-input bg-background px-2 text-xs"
                value={selectedEndpointId()}
                onChange={(event) => {
                  setSelectedEndpointId(event.currentTarget.value);
                  const endpoint = endpoints().find(
                    (entry) => entry.id === event.currentTarget.value,
                  );
                  setMethod(endpoint?.methods[0] ?? "GET");
                }}
              >
                <For each={endpoints()}>
                  {(endpoint) => <option value={endpoint.id}>{endpoint.id}</option>}
                </For>
              </select>
            </label>
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">Method</span>
              <select
                class="h-8 w-full border border-input bg-background px-2 text-xs"
                value={method()}
                onChange={(event) => setMethod(event.currentTarget.value)}
              >
                <For each={selectedEndpoint()?.methods ?? []}>
                  {(entry) => <option value={entry}>{entry}</option>}
                </For>
              </select>
            </label>
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">Credential ID</span>
              <input
                class="h-8 w-full border border-input bg-background px-2 text-xs"
                value={credentialId()}
                onInput={(event) => setCredentialId(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">Header</span>
              <input
                class="h-8 w-full border border-input bg-background px-2 text-xs"
                value={headerName()}
                onInput={(event) => setHeaderName(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-xs md:col-span-2">
              <span class="text-muted-foreground">Secret value</span>
              <input
                type="password"
                class="h-8 w-full border border-input bg-background px-2 text-xs"
                value={headerValue()}
                onInput={(event) => setHeaderValue(event.currentTarget.value)}
              />
            </label>
          </div>
          <div class="mt-3 flex items-center justify-between gap-3">
            <p class="truncate text-xs text-muted-foreground">
              {selectedEndpoint()?.credentialAudience ?? "No credential audience"}
            </p>
            <Button size="sm" variant="outline" disabled={props.busy} onClick={saveCredential}>
              <KeyIcon class="size-3.5" />
              Save credential
            </Button>
          </div>
        </div>
      </Show>
    </div>
  );
}

function PluginActivationRow(props: {
  activation: PluginActivationInfo;
  application?: PluginApplicationInfo;
  busy: boolean;
  onToggle: (activation: PluginActivationInfo) => void;
  onDelete: (activation: PluginActivationInfo) => void;
}) {
  const pluginId = () => props.application?.plugin_id ?? props.activation.application_id;
  const scope = () => (props.activation.device_id ? "Device" : "User");

  return (
    <div class="flex items-center justify-between gap-3 border-b border-border/60 py-3 last:border-0">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <h4 class="truncate text-sm font-medium">{pluginId()}</h4>
          <span class="border border-border/60 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            {scope()}
          </span>
          <span class="text-xs text-muted-foreground">
            {props.activation.enabled ? "Enabled" : "Disabled"}
          </span>
        </div>
        <p class="mt-1 truncate text-xs text-muted-foreground">{props.activation.id}</p>
      </div>
      <div class="flex shrink-0 items-center gap-1">
        <Button
          size="icon-sm"
          variant="ghost"
          title={props.activation.enabled ? "Disable on this device" : "Enable on this device"}
          disabled={props.busy}
          onClick={() => props.onToggle(props.activation)}
        >
          <PowerIcon class="size-3.5" />
        </Button>
        <Button
          size="icon-sm"
          variant="ghost"
          title="Remove from this device"
          disabled={props.busy}
          onClick={() => props.onDelete(props.activation)}
        >
          <Trash2Icon class="size-3.5" />
        </Button>
      </div>
    </div>
  );
}

function PluginPackageRow(props: {
  packageInfo: PluginPackageInfo;
  installed: boolean;
  busy: boolean;
  workspaceRole?: string | null;
  onApply: (packageInfo: PluginPackageInfo) => void;
}) {
  const canApply = () => canApplyPluginPackage(props.packageInfo, props.workspaceRole);

  return (
    <div class="flex items-center justify-between gap-3 border-b border-border/60 py-3 last:border-0">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <h4 class="truncate text-sm font-medium">{packageLabel(props.packageInfo)}</h4>
          <span class="border border-border/60 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
            {scopeLabel(props.packageInfo.owner_scope_kind)}
          </span>
          <Show when={props.installed}>
            <span class="text-xs text-muted-foreground">Installed</span>
          </Show>
        </div>
        <p class="mt-1 truncate text-xs text-muted-foreground">
          {props.packageInfo.bundle_hash || "No pinned bundle"}
        </p>
      </div>
      <Button
        size="sm"
        variant="outline"
        disabled={props.busy || !canApply()}
        onClick={() => props.onApply(props.packageInfo)}
      >
        <CheckIcon class="size-3.5" />
        {props.installed ? "Reapply" : "Apply"}
      </Button>
    </div>
  );
}

export function CommunityPluginsSection(props: CommunityPluginsSectionProps) {
  const workspaceId = () => currentWorkspaceId();
  const workspaces = useWorkspaces();
  const queryClient = useQueryClient();
  let localArchiveInput: HTMLInputElement | undefined;
  const [sourceKind, setSourceKind] = createSignal<SourceKind>("remote_https_url");
  const [selectedOwnerScopeKind, setSelectedOwnerScopeKind] =
    createSignal<PluginOwnerScopeKind | null>(null);
  const [sourceUrl, setSourceUrl] = createSignal("");
  const [selectedFile, setSelectedFile] = createSignal<File | null>(null);
  const [candidate, setCandidate] = createSignal<PluginBundleCandidateInfo | null>(null);
  const [busyAction, setBusyAction] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [info, setInfo] = createSignal<string | null>(null);

  const applications = createQuery(() => ({
    queryKey: ["plugin-applications", workspaceId()],
    queryFn: () => pluginsApi.listApplications(workspaceId()!),
    enabled: Boolean(workspaceId()),
  }));

  const userPackages = createQuery(() => ({
    queryKey: ["plugin-packages", "user"],
    queryFn: pluginsApi.listUserPackages,
  }));

  const workspacePackages = createQuery(() => ({
    queryKey: ["plugin-packages", "workspace", workspaceId()],
    queryFn: () => pluginsApi.listWorkspacePackages(workspaceId()!),
    enabled: Boolean(workspaceId()),
  }));

  const activations = createQuery(() => ({
    queryKey: ["plugin-activations"],
    queryFn: pluginsApi.listActivations,
  }));
  const runtimeApplications = createQuery(() => ({
    queryKey: ["plugin-runtime-applications", workspaceId()],
    queryFn: () => props.listRuntimeApplications(workspaceId()!),
    enabled: Boolean(workspaceId()),
  }));

  const applicationRows = () =>
    ((applications.data ?? []) as readonly PluginApplicationInfo[]).filter(
      (application) => !application.deleted_at,
    );
  const activationRows = () =>
    ((activations.data ?? []) as readonly PluginActivationInfo[]).filter(
      (activation) => !activation.deleted_at,
    );
  const userPackageRows = () => (userPackages.data ?? []) as readonly PluginPackageInfo[];
  const workspacePackageRows = () => (workspacePackages.data ?? []) as readonly PluginPackageInfo[];
  const installedPackageIds = createMemo(
    () => new Set(applicationRows().map((application) => application.package_id)),
  );
  const applicationsById = createMemo(
    () => new Map(applicationRows().map((application) => [application.id, application] as const)),
  );
  const currentActivationForApplication = (application: PluginApplicationInfo) => {
    return activationRows().find((activation) => activation.application_id === application.id);
  };
  const currentRuntimeForApplication = (application: PluginApplicationInfo) => {
    return (runtimeApplications.data ?? []).find(
      (runtime) => runtime.applicationId === application.id,
    );
  };
  const packages = createMemo(() => [...userPackageRows(), ...workspacePackageRows()]);
  const candidateScopes = createMemo(() => {
    const current = candidate();
    return current ? sourceScopeSummary(current) : [];
  });
  const showOwnerScopeChoice = createMemo(() => candidateScopes().length > 1);
  const resolvedOwnerScope = createMemo(
    () => selectedOwnerScopeKind() ?? candidate()?.owner_scope_kind ?? null,
  );
  const currentWorkspace = () =>
    workspaces.allWorkspaces().find((workspace) => workspace.id === workspaceId()) ?? null;
  const applicationsForCandidate = (current: PluginBundleCandidateInfo) => {
    if (!current.plugin_id) return [];
    const targetWorkspaceId = current.workspace_id ?? workspaceId();
    return applicationRows().filter(
      (application) =>
        application.plugin_id === current.plugin_id &&
        (!targetWorkspaceId || application.workspace_id === targetWorkspaceId),
    );
  };
  const currentWorkspaceRole = () => {
    const workspace = currentWorkspace();
    return workspace && "current_user_base_role" in workspace
      ? workspace.current_user_base_role
      : null;
  };
  const canRouteWorkspaceCandidate = () => {
    const role = currentWorkspaceRole();
    return role === "owner" || role === "admin";
  };
  const manifestRoutingWorkspaceId = () => (canRouteWorkspaceCandidate() ? workspaceId() : null);

  const refreshPluginManagement = () => {
    const id = workspaceId();
    void queryClient.invalidateQueries({ queryKey: ["plugin-packages", "user"] });
    void queryClient.invalidateQueries({ queryKey: ["plugin-activations"] });
    if (id) {
      void queryClient.invalidateQueries({ queryKey: ["plugin-packages", "workspace", id] });
      void queryClient.invalidateQueries({ queryKey: ["plugin-applications", id] });
      void queryClient.invalidateQueries({ queryKey: ["plugin-runtime-applications", id] });
    }
  };

  const mergePromotedPluginManagement = (promotion: {
    package: PluginPackageInfo;
    application?: PluginApplicationInfo;
    activation?: PluginActivationInfo;
  }) => {
    const packageKey =
      promotion.package.owner_scope_kind === "workspace"
        ? ["plugin-packages", "workspace", promotion.package.owner_workspace_id ?? workspaceId()]
        : ["plugin-packages", "user"];
    queryClient.setQueryData<readonly PluginPackageInfo[]>(packageKey, (current) =>
      upsertPluginPackage(current, promotion.package),
    );
    if (promotion.application) {
      const application = promotion.application;
      queryClient.setQueryData<readonly PluginApplicationInfo[]>(
        ["plugin-applications", application.workspace_id],
        (current) => upsertPluginApplication(current, application),
      );
    }
    if (promotion.activation) {
      const activation = promotion.activation;
      queryClient.setQueryData<readonly PluginActivationInfo[]>(["plugin-activations"], (current) =>
        upsertPluginActivation(current, activation),
      );
    }
  };
  const mergePluginApplication = (application: PluginApplicationInfo) => {
    queryClient.setQueryData<readonly PluginApplicationInfo[]>(
      ["plugin-applications", application.workspace_id],
      (current) => upsertPluginApplication(current, application),
    );
  };

  const saveAppliedStatePin = async (
    packageInfo: PluginPackageInfo,
    application: PluginApplicationInfo,
    activation: PluginActivationInfo | undefined,
  ) => {
    let applyPinError: unknown;
    try {
      await saveAppliedPluginStatePin(packageInfo, application, activation);
    } catch (error) {
      applyPinError = error;
    }

    if (activation) {
      const runtime = (await props.listRuntimeApplications(application.workspace_id)).find(
        (entry) =>
          entry.applicationId === application.id &&
          entry.activationId === activation.id &&
          entry.packageId === application.package_id,
      );
      if (runtime) {
        await saveRuntimeDescriptorPluginStatePin(runtime);
        return;
      }
    }

    if (applyPinError) {
      throw applyPinError;
    }
  };

  const runAction = async (action: string, fn: () => Promise<void>) => {
    setBusyAction(action);
    setError(null);
    setInfo(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Plugin operation failed");
    } finally {
      setBusyAction(null);
    }
  };

  const handleCreateCandidate = async () => {
    await runAction("create-candidate", async () => {
      const created = await pluginsApi.createCandidate({
        workspaceId: manifestRoutingWorkspaceId(),
        ...(await candidateSourceInput()),
      });
      setCandidate(created);
      setSelectedOwnerScopeKind(created.owner_scope_kind);
      setInfo("Plugin ready for review.");
      refreshPluginManagement();
    });
  };

  const candidateSourceInput = async () =>
    sourceKind() === "local_upload"
      ? {
          sourceKind: "local_upload" as const,
          archiveBase64: selectedFile()
            ? await arrayBufferToBase64(await selectedFile()!.arrayBuffer())
            : "",
        }
      : {
          sourceKind: "remote_https_url" as const,
          sourceUrl: sourceUrl().trim(),
        };

  const candidateForSelectedScope = async () => {
    const current = candidate();
    if (!current) return null;
    const scope = resolvedOwnerScope();
    if (!scope || scope === current.owner_scope_kind) return current;
    const id = workspaceId();
    if (scope === "workspace" && !id) throw new Error("workspace_required");
    if (scope === "workspace" && !canRouteWorkspaceCandidate()) {
      throw new Error("workspace_admin_required");
    }

    const created = await pluginsApi.createCandidate({
      ownerScopeKind: scope,
      workspaceId: id,
      ...(await candidateSourceInput()),
    });
    setCandidate(created);
    setSelectedOwnerScopeKind(created.owner_scope_kind);
    return created;
  };

  const handlePromoteCandidate = async () => {
    await runAction("promote-candidate", async () => {
      const auth = authState();
      const device = deviceState();
      if (!auth || !device?.deviceId || !cryptoWorkerReady()) {
        throw new Error("device_signing_required");
      }
      const current = await candidateForSelectedScope();
      if (!current) return;
      const summary = current.approval_summary;
      if (!summary) throw new Error("plugin_approval_summary_missing");

      const actor = strictRecord(summary.actor, "plugin_approval_actor_invalid");
      const approval = strictRecord(summary.subject, "plugin_approval_subject_invalid");
      const approvalEventHash = summary.approval_event_hash;
      const approvalEpoch = summary.approval_epoch;
      const previousApprovalEventHash = summary.previous_approval_event_hash;
      const createdAtMs = summary.created_at_ms;
      if (
        !approvalEventHash ||
        typeof approvalEpoch !== "number" ||
        !previousApprovalEventHash ||
        typeof createdAtMs !== "number"
      ) {
        throw new Error("plugin_approval_summary_invalid");
      }

      const signed = await getCryptoWorker().signPluginBundleApproval({
        actor,
        approval,
      });
      const payload: PluginApprovalPayload = {
        approval_event_hash: approvalEventHash,
        approval_epoch: approvalEpoch,
        previous_approval_event_hash: previousApprovalEventHash,
        created_at_ms: createdAtMs,
        hybrid_signature: signed.signature,
      };
      await Promise.all(
        applicationsForCandidate(current).map((application) =>
          Promise.resolve(
            props.closeRuntimeByApplication?.(application.id, "plugin_bundle_updated"),
          ),
        ),
      );
      const promotion = await pluginsApi.promoteCandidate(
        current.owner_scope_kind,
        current.id,
        payload,
        current.workspace_id ?? workspaceId(),
      );
      mergePromotedPluginManagement(promotion);
      if (promotion.application) {
        await props.closeRuntimeByApplication?.(promotion.application.id, "plugin_bundle_updated");
      }
      await savePromotedPluginStatePin(promotion);
      if (promotion.application) {
        props.requestRuntimeApplicationsRefresh(promotion.application.workspace_id);
      }
      setInfo("Plugin approved.");
    });
  };

  const handleApplyPackage = async (packageInfo: PluginPackageInfo) => {
    await runAction(`apply-${packageInfo.id}`, async () => {
      const id = workspaceId();
      if (!id) throw new Error("workspace_required");
      const { application, activation } = await pluginsApi.applyPackage(id, packageInfo.id);
      mergePluginApplication(application);
      if (activation) {
        queryClient.setQueryData<readonly PluginActivationInfo[]>(
          ["plugin-activations"],
          (current) => upsertPluginActivation(current, activation),
        );
      }
      await saveAppliedStatePin(packageInfo, application, activation);
      setInfo("Plugin applied to workspace.");
      props.requestRuntimeApplicationsRefresh(application.workspace_id);
    });
  };

  const handleToggleApplication = async (application: PluginApplicationInfo) => {
    await runAction(`toggle-${application.id}`, async () => {
      const nextEnabled = !application.enabled;
      const revokesRuntime = application.enabled;
      if (revokesRuntime) props.beginRuntimeApplicationRevocation?.(application.id);
      try {
        const updated = await pluginsApi.updateApplication(
          application.workspace_id,
          application.id,
          {
            enabled: nextEnabled,
          },
        );
        mergePluginApplication(updated);
        if (application.enabled) {
          await props.closeRuntimeByApplication?.(application.id, "plugin_application_disabled");
          props.requestRuntimeApplicationsRefresh(updated.workspace_id);
        } else {
          const packageInfo = packages().find((entry) => entry.id === updated.package_id);
          const activation =
            currentActivationForApplication(updated) ??
            currentActivationForApplication(application);
          if (packageInfo && activation) {
            await saveAppliedStatePin(packageInfo, updated, activation);
          }
          props.requestRuntimeApplicationsRefresh(updated.workspace_id);
        }
        setInfo(application.enabled ? "Plugin disabled." : "Plugin enabled.");
      } finally {
        if (revokesRuntime) props.releaseRuntimeApplicationRevocation?.(application.id);
      }
    });
  };

  const handleSetApplicationPolicy = async (
    application: PluginApplicationInfo,
    workspacePolicyResult: "allowed" | "denied",
  ) => {
    await runAction(`policy-${application.id}`, async () => {
      const revokesRuntime = workspacePolicyResult === "denied";
      if (revokesRuntime) props.beginRuntimeApplicationRevocation?.(application.id);
      try {
        const updated = await pluginsApi.updateApplication(
          application.workspace_id,
          application.id,
          {
            workspace_policy_result: workspacePolicyResult,
          },
        );
        mergePluginApplication(updated);
        if (workspacePolicyResult === "denied") {
          await props.closeRuntimeByApplication?.(
            application.id,
            "plugin_application_policy_denied",
          );
          props.requestRuntimeApplicationsRefresh(updated.workspace_id);
        } else {
          const packageInfo = packages().find((entry) => entry.id === updated.package_id);
          const activation =
            currentActivationForApplication(updated) ??
            currentActivationForApplication(application);
          if (packageInfo && activation) {
            await saveAppliedStatePin(packageInfo, updated, activation);
          }
          props.requestRuntimeApplicationsRefresh(updated.workspace_id);
        }
        setInfo(workspacePolicyResult === "allowed" ? "Plugin allowed." : "Plugin denied.");
      } finally {
        if (revokesRuntime) props.releaseRuntimeApplicationRevocation?.(application.id);
      }
    });
  };

  const handleSaveCredential = async (
    application: PluginApplicationInfo,
    activation: PluginActivationInfo,
    endpoint: PluginCredentialEndpointInfo,
    credentialId: string,
    headerName: string,
    headerValue: string,
    method: string,
  ) => {
    await runAction(`credential-${application.id}`, async () => {
      const auth = authState();
      const device = deviceState();
      if (!auth || !device?.deviceId || !cryptoWorkerReady()) {
        throw new Error("device_credential_storage_required");
      }
      const normalizedCredentialId = credentialId.trim();
      const normalizedHeaderName = headerName.trim().toLowerCase();
      const normalizedHeaderValue = headerValue.trim();
      if (!normalizedCredentialId || !normalizedHeaderName || !normalizedHeaderValue) {
        throw new Error("plugin_credential_input_required");
      }

      await props.storeCredential({
        credentialId: normalizedCredentialId,
        pluginId: application.plugin_id,
        workspaceId: application.workspace_id,
        packageId: application.package_id,
        applicationId: application.id,
        activationId: activation.id,
        userId: auth.user.id,
        deviceId: device.deviceId,
        audience: endpoint.credentialAudience,
        endpoint: endpoint.url,
        method,
        headers: { [normalizedHeaderName]: normalizedHeaderValue },
      });
      setInfo("Plugin credential saved.");
    });
  };

  const handleRevokeConsent = async (application: PluginApplicationInfo) => {
    await runAction(`revoke-consent-${application.id}`, async () => {
      const auth = authState();
      const device = deviceState();
      if (!auth || !device?.deviceId || !cryptoWorkerReady()) {
        throw new Error("device_consent_signing_required");
      }
      if (
        !device.deviceKeyCheckpointSequence ||
        typeof device.deviceKeyCheckpointHash !== "string"
      ) {
        throw new Error("device_key_checkpoint_required");
      }
      const runtime = currentRuntimeForApplication(application);
      if (!runtime) throw new Error("plugin_consent_not_allowed");

      await runWithPluginRuntimeApplicationRevocation(application.id, props, async () => {
        const descriptor = consentDescriptorFromRuntime(runtime);
        await props.closeRuntimeByApplication?.(application.id, "plugin_consent_revoked");
        await props.submitConsentDecision(descriptor, "revoke", {
          userId: auth.user.id,
          deviceId: device.deviceId,
          sign: async (consent) =>
            getCryptoWorker().signPluginConsentEvent({
              consent,
              keyCheckpointSequence: device.deviceKeyCheckpointSequence!,
              keyCheckpointHash: device.deviceKeyCheckpointHash!,
            }),
          appendConsent: (body) =>
            pluginsApi.appendConsentEvent(
              descriptor.workspaceId,
              descriptor.applicationId,
              body as Parameters<typeof pluginsApi.appendConsentEvent>[2],
            ),
          getStatePin: getPluginStatePin,
          saveConsentPin: savePluginConsentPin,
          nowMs: Date.now,
        });
        setInfo("Plugin consent revoked.");
        props.requestRuntimeApplicationsRefresh(application.workspace_id);
        refreshPluginManagement();
      });
    });
  };

  const handleDeleteApplication = async (application: PluginApplicationInfo) => {
    await runAction(`delete-${application.id}`, async () => {
      props.beginRuntimeApplicationRevocation?.(application.id);
      try {
        await props.closeRuntimeByApplication?.(application.id, "plugin_application_deleted");
        await pluginsApi.deleteApplication(application.workspace_id, application.id);
        await purgeDeletedApplicationLocalData(
          application,
          activationRows(),
          deviceState()?.deviceId,
          props.purgeLocalData,
        );
        setInfo("Plugin removed from workspace.");
        props.requestRuntimeApplicationsRefresh(application.workspace_id);
        refreshPluginManagement();
      } finally {
        props.releaseRuntimeApplicationRevocation?.(application.id);
      }
    });
  };

  const handleToggleActivation = async (activation: PluginActivationInfo) => {
    await runAction(`toggle-activation-${activation.id}`, async () => {
      const updateActivation = async () => {
        if (activation.enabled) {
          await props.closeRuntimeByApplication?.(
            activation.application_id,
            "plugin_activation_disabled",
          );
        }
        await pluginsApi.updateActivation(activation.id, {
          enabled: !activation.enabled,
        });
        if (!activation.enabled) {
          props.requestRuntimeApplicationsRefresh(activation.workspace_id);
        }
        setInfo(
          activation.enabled ? "Plugin disabled on this device." : "Plugin enabled on this device.",
        );
        refreshPluginManagement();
      };

      if (activation.enabled) {
        await runWithPluginRuntimeApplicationRevocation(
          activation.application_id,
          props,
          updateActivation,
        );
      } else {
        await updateActivation();
      }
    });
  };

  const handleDeleteActivation = async (activation: PluginActivationInfo) => {
    await runAction(`delete-activation-${activation.id}`, async () => {
      await runWithPluginRuntimeApplicationRevocation(
        activation.application_id,
        props,
        async () => {
          await props.closeRuntimeByApplication?.(
            activation.application_id,
            "plugin_activation_deleted",
          );
          const deleted = await pluginsApi.deleteActivation(activation.id);
          await purgeDeletedActivationLocalData(
            deleted,
            applicationsById().get(deleted.application_id) ??
              applicationsById().get(activation.application_id),
            deviceState()?.deviceId,
            props.purgeLocalData,
          );
          setInfo("Plugin removed from this device.");
          props.requestRuntimeApplicationsRefresh(deleted.workspace_id ?? activation.workspace_id);
          refreshPluginManagement();
        },
      );
    });
  };

  return (
    <div class="p-6 space-y-6" data-refmd-plugin-management-busy-action={busyAction() ?? ""}>
      <div>
        <h3 class="text-lg font-semibold mb-1">Community Plugins</h3>
        <p class="text-sm text-muted-foreground">
          Add and manage plugins for the current workspace.
        </p>
      </div>

      <Show when={error()}>
        {(message) => (
          <Alert variant="destructive">
            <AlertDescription>{message()}</AlertDescription>
          </Alert>
        )}
      </Show>
      <Show when={info()}>
        {(message) => (
          <Alert>
            <AlertDescription>{message()}</AlertDescription>
          </Alert>
        )}
      </Show>

      <section class="space-y-4 border border-border/60 p-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h4 class="text-sm font-medium">Add Plugin</h4>
            <p class="mt-1 text-xs text-muted-foreground">Remote URL or local archive.</p>
          </div>
          <div class="flex items-center gap-2">
            <ScopeButton
              selected={sourceKind() === "remote_https_url"}
              onClick={() => setSourceKind("remote_https_url")}
            >
              <LinkIcon class="size-3.5" />
              URL
            </ScopeButton>
            <ScopeButton
              selected={sourceKind() === "local_upload"}
              onClick={() => setSourceKind("local_upload")}
            >
              <UploadIcon class="size-3.5" />
              Upload
            </ScopeButton>
          </div>
        </div>

        <Show
          when={sourceKind() === "remote_https_url"}
          fallback={
            <div class="flex h-10 w-full min-w-0 items-center border border-border/60 bg-muted/40 shadow-[var(--glass-shadow-inset)]">
              <input
                ref={(element) => {
                  localArchiveInput = element;
                }}
                type="file"
                accept=".zip,application/zip"
                class="sr-only"
                aria-label="Plugin archive"
                onInput={(event) => setSelectedFile(event.currentTarget.files?.[0] ?? null)}
              />
              <Button
                type="button"
                variant="secondary"
                size="sm"
                class="ml-2 h-7 shrink-0 px-3"
                onClick={() => localArchiveInput?.click()}
              >
                Choose file
              </Button>
              <span class="min-w-0 flex-1 truncate px-3 text-sm text-muted-foreground">
                {selectedFile()?.name ?? "No file chosen"}
              </span>
            </div>
          }
        >
          <Input
            type="url"
            placeholder="https://example.com/plugin.zip"
            value={sourceUrl()}
            onInput={(event) => setSourceUrl(event.currentTarget.value)}
          />
        </Show>

        <Button
          type="button"
          size="sm"
          disabled={busyAction() === "create-candidate"}
          onClick={() => void handleCreateCandidate()}
        >
          <PackagePlusIcon class="size-3.5" />
          Review Plugin
        </Button>

        <Show when={candidate()}>
          {(currentCandidate) => (
            <div class="space-y-3">
              <PluginReviewSummary candidate={currentCandidate()} />
              <Show
                when={showOwnerScopeChoice()}
                fallback={
                  <p class="text-xs text-muted-foreground">
                    {scopeChoiceLabel(currentCandidate().owner_scope_kind)}
                  </p>
                }
              >
                <div class="flex flex-wrap items-center gap-2">
                  <span class="text-xs text-muted-foreground">Install as</span>
                  <For each={candidateScopes()}>
                    {(scope) => (
                      <ScopeButton
                        selected={resolvedOwnerScope() === scope}
                        disabled={
                          scope === "workspace" && (!workspaceId() || !canRouteWorkspaceCandidate())
                        }
                        onClick={() => setSelectedOwnerScopeKind(scope)}
                      >
                        {scopeChoiceLabel(scope)}
                      </ScopeButton>
                    )}
                  </For>
                </div>
              </Show>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={
                  !currentCandidate().approval_summary || busyAction() === "promote-candidate"
                }
                onClick={() => void handlePromoteCandidate()}
              >
                <CheckIcon class="size-3.5" />
                Approve Plugin
              </Button>
            </div>
          )}
        </Show>
      </section>

      <section class="space-y-3">
        <div class="flex items-center justify-between gap-3">
          <h4 class="text-sm font-medium">Installed</h4>
          <Button size="icon-sm" variant="ghost" title="Refresh" onClick={refreshPluginManagement}>
            <RefreshCwIcon class="size-3.5" />
          </Button>
        </div>
        <Show
          when={!applications.isLoading}
          fallback={
            <div class="flex justify-center py-6">
              <Spinner class="size-4" />
            </div>
          }
        >
          <Show
            when={applicationRows().length > 0}
            fallback={<ListEmpty>No plugins installed.</ListEmpty>}
          >
            <div class="border-y border-border/60">
              <For each={applicationRows()}>
                {(application) => (
                  <PluginApplicationRow
                    application={application}
                    activation={currentActivationForApplication(application)}
                    busy={Boolean(busyAction())}
                    canManagePolicy={canManagePluginApplicationPolicy(
                      application,
                      currentWorkspaceRole(),
                    )}
                    canRevokeConsent={Boolean(currentRuntimeForApplication(application))}
                    onSaveCredential={handleSaveCredential}
                    onSetPolicy={handleSetApplicationPolicy}
                    onToggle={handleToggleApplication}
                    onRevokeConsent={handleRevokeConsent}
                    onDelete={handleDeleteApplication}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-medium">Device access</h4>
        <Show
          when={!activations.isLoading}
          fallback={
            <div class="flex justify-center py-6">
              <Spinner class="size-4" />
            </div>
          }
        >
          <Show
            when={activationRows().length > 0}
            fallback={<ListEmpty>No device-specific plugin access.</ListEmpty>}
          >
            <div class="border-y border-border/60">
              <For each={activationRows()}>
                {(activation) => (
                  <PluginActivationRow
                    activation={activation}
                    application={applicationsById().get(activation.application_id)}
                    busy={Boolean(busyAction())}
                    onToggle={handleToggleActivation}
                    onDelete={handleDeleteActivation}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </section>

      <section class="space-y-3">
        <h4 class="text-sm font-medium">Available plugins</h4>
        <Show
          when={!userPackages.isLoading && !workspacePackages.isLoading}
          fallback={
            <div class="flex justify-center py-6">
              <Spinner class="size-4" />
            </div>
          }
        >
          <Show
            when={packages().length > 0}
            fallback={<ListEmpty>No plugins available.</ListEmpty>}
          >
            <div class="border-y border-border/60">
              <For each={packages()}>
                {(packageInfo) => (
                  <PluginPackageRow
                    packageInfo={packageInfo}
                    installed={installedPackageIds().has(packageInfo.id)}
                    busy={Boolean(busyAction())}
                    workspaceRole={currentWorkspaceRole()}
                    onApply={handleApplyPackage}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </section>
    </div>
  );
}
