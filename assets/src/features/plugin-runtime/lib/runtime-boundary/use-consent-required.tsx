import {
  createEffect,
  createSignal,
  For,
  onCleanup,
  Show,
  untrack,
  type Accessor,
  type JSX,
} from "solid-js";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { client, throwIfError, withUserRrpParams } from "@/shared/api/core";
import type { components } from "@/shared/api/schema";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { HybridSignature } from "@/shared/lib/crypto/signature";
import {
  getPluginConsentPin,
  getPluginStatePin,
  savePluginConsentPin,
  savePluginStatePin,
  type PluginConsentPin,
  type PluginStatePin,
} from "@/shared/lib/crypto/trust-store";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import {
  assertPluginManifestAuthorityHashes,
  derivePluginManifestAuthority,
} from "./manifest-authority";
import type { PluginNetworkProxyRegistration } from "../network/host-network";
import {
  MAX_WORKSPACE_DOCUMENT_QUERY_BYTES,
  MAX_WORKSPACE_DOCUMENT_QUERY_DOCUMENTS,
} from "../../model/host-ui/host-ui-validation";
import { PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT } from "./use-runtime-applications";
import { guardedPluginRuntimeWorkspaceRequest } from "./runtime-workspace-revocation";
import type { PluginRuntimeApplicationDescriptor } from "./runtime-types";

interface PluginConsentRequiredEnvelope {
  applications?: readonly PluginConsentRequiredEntry[];
}

interface PluginConsentRequiredEntry {
  plugin_id?: string;
  package_id?: string;
  application_id?: string;
  activation_id?: string;
  owner_scope_kind?: string;
  application_scope_kind?: string;
  workspace_id?: string;
  state_head_hash?: string;
  approval_event_hash?: string;
  consent_head_hash?: string | null;
  consent_epoch?: number | null;
  version?: string;
  bundle_hash?: string;
  manifest_hash?: string;
  resource_manifest_hash?: string;
  permissions_hash?: string;
  endpoint_hash?: string;
  renderer_slots_hash?: string;
  document_scope_hash?: string;
  signer_device_id?: string;
  signer_user_id?: string;
  document_scope?: Record<string, unknown>;
  title?: string;
  permissions?: readonly string[];
  network_endpoints?: readonly Record<string, unknown>[];
  renderer_slots?: readonly Record<string, unknown>[];
  document_scopes?: readonly Record<string, unknown>[];
  high_risk_consents?: readonly string[];
  author?: string;
}

const PLUGIN_CONSENT_REQUIRED_REFRESH_MS = 120_000;

export interface PluginConsentRequiredDescriptor {
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  applicationScopeKind: string;
  workspaceId: string;
  stateHeadHash: string;
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

export interface PluginConsentSubject extends Record<string, StrictJsonValue> {
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

interface ConsentEventResponse {
  consent_event?: {
    event_hash?: string;
    decision?: string;
    consent_epoch?: number;
  };
}

interface PluginConsentActionDependencies {
  userId: string;
  deviceId: string;
  sign(consent: PluginConsentSubject): Promise<{ signature: HybridSignature }>;
  appendConsent(body: Record<string, StrictJsonValue>): Promise<ConsentEventResponse>;
  getStatePin(
    workspaceId: string,
    packageId: string,
    applicationId: string,
    activationId: string,
  ): Promise<PluginStatePin | null>;
  saveConsentPin(pin: PluginConsentPin): Promise<void>;
  nowMs(): number;
}

interface PluginConsentRequiredOptions {
  onConsentChanged?: () => void;
  networkProxyRegistration?: () => PluginNetworkProxyRegistration | null;
  runtimeApplications?: Accessor<readonly PluginRuntimeApplicationDescriptor[]>;
  enabled?: Accessor<boolean>;
}

export function usePluginConsentRequired(
  workspaceId: Accessor<string | null>,
  options: PluginConsentRequiredOptions = {},
): { view: Accessor<JSX.Element> } {
  const [descriptors, setDescriptors] = createSignal<readonly PluginConsentRequiredDescriptor[]>(
    [],
  );
  const [busyApplicationId, setBusyApplicationId] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const suppressed = new Set<string>();
  let refreshTimer: ReturnType<typeof setInterval> | undefined;
  let generation = 0;
  let refreshRequestId = 0;
  const enabled = () => options.enabled?.() ?? true;
  const currentRuntimeApplications = () => untrack(() => options.runtimeApplications?.());

  const refresh = async (
    currentWorkspaceId = workspaceId(),
    runtimeApplications = currentRuntimeApplications(),
  ) => {
    const requestId = ++refreshRequestId;
    if (!enabled() || !currentWorkspaceId || !authState() || !deviceState()?.deviceId) {
      if (requestId === refreshRequestId) setDescriptors([]);
      return;
    }

    try {
      const next = await listPluginConsentRequired(currentWorkspaceId, {
        runtimeApplications,
      });
      if (requestId === refreshRequestId) {
        setDescriptors(next.filter((descriptor) => !suppressed.has(descriptorKey(descriptor))));
      }
    } catch {
      if (requestId === refreshRequestId) setError("Plugin consent state could not be refreshed.");
    }
  };

  createEffect(() => {
    generation += 1;
    const currentGeneration = generation;
    const currentWorkspaceId = workspaceId();
    const auth = authState();
    const device = deviceState();
    const runtimeApplications = currentRuntimeApplications();

    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = undefined;
    }

    if (!enabled() || !currentWorkspaceId || !auth || !device?.deviceId) {
      setDescriptors([]);
      return;
    }

    void refresh(currentWorkspaceId, runtimeApplications);
    refreshTimer = setInterval(() => {
      if (generation === currentGeneration) {
        void refresh(currentWorkspaceId, currentRuntimeApplications());
      }
    }, PLUGIN_CONSENT_REQUIRED_REFRESH_MS);
  });

  const refreshListener = (event: Event) => {
    if (!enabled()) return;
    const currentWorkspaceId = workspaceId();
    if (!currentWorkspaceId) return;
    const detail =
      event instanceof CustomEvent && typeof event.detail === "object" ? event.detail : null;
    const targetWorkspaceId =
      detail && "workspaceId" in detail && typeof detail.workspaceId === "string"
        ? detail.workspaceId
        : null;
    if (!targetWorkspaceId || targetWorkspaceId === currentWorkspaceId) {
      setDescriptors([]);
      void refresh(currentWorkspaceId, currentRuntimeApplications());
    }
  };
  window.addEventListener(PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT, refreshListener);

  onCleanup(() => {
    generation += 1;
    refreshRequestId += 1;
    if (refreshTimer) clearInterval(refreshTimer);
    window.removeEventListener(PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT, refreshListener);
  });

  const decide = async (
    descriptor: PluginConsentRequiredDescriptor,
    decision: PluginConsentSubject["decision"],
  ) => {
    const auth = authState();
    const device = deviceState();
    if (!auth || !device?.deviceId || !cryptoWorkerReady()) {
      setError(pluginConsentDecisionErrorMessage(new Error("device_consent_signing_required")));
      return;
    }
    if (!device.deviceKeyCheckpointSequence || typeof device.deviceKeyCheckpointHash !== "string") {
      setError(pluginConsentDecisionErrorMessage(new Error("device_key_checkpoint_required")));
      return;
    }

    setBusyApplicationId(descriptor.applicationId);
    setError(null);
    try {
      if (decision === "allow") {
        const statePin = await getPluginStatePin(
          descriptor.workspaceId,
          descriptor.packageId,
          descriptor.applicationId,
          descriptor.activationId,
        );
        if (!statePin) {
          await savePluginConsentDescriptorStatePin(descriptor);
        }
      }
      await submitPluginConsentDecision(descriptor, decision, {
        userId: auth.user.id,
        deviceId: device.deviceId,
        sign: async (consent) =>
          getCryptoWorker().signPluginConsentEvent({
            consent,
            keyCheckpointSequence: device.deviceKeyCheckpointSequence!,
            keyCheckpointHash: device.deviceKeyCheckpointHash!,
          }),
        appendConsent: (body) => appendPluginConsentEvent(descriptor, body),
        getStatePin: getPluginStatePin,
        saveConsentPin: savePluginConsentPin,
        nowMs: Date.now,
      });
      suppressed.add(descriptorKey(descriptor));
      setDescriptors((prev) =>
        prev.filter((entry) => entry.applicationId !== descriptor.applicationId),
      );
      options.onConsentChanged?.();
      void refresh();
    } catch (error) {
      setError(pluginConsentDecisionErrorMessage(error));
    } finally {
      setBusyApplicationId(null);
    }
  };

  const canSubmitConsentDecision = () => {
    const auth = authState();
    const device = deviceState();
    return Boolean(auth && device?.deviceId && cryptoWorkerReady());
  };

  const dismiss = (descriptor: PluginConsentRequiredDescriptor) => {
    suppressed.add(descriptorKey(descriptor));
    setError(null);
    setDescriptors((prev) =>
      prev.filter((entry) => entry.applicationId !== descriptor.applicationId),
    );
  };

  const view = () => {
    return (
      <Show when={descriptors()[0]}>
        {(descriptor) => (
          <Dialog open>
            <DialogContent
              showCloseButton={false}
              class="grid max-h-[calc(100vh-2rem)] max-w-lg grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden"
            >
              <DialogHeader>
                <DialogTitle>Plugin Consent</DialogTitle>
                <DialogDescription>{descriptor().title}</DialogDescription>
              </DialogHeader>
              <div class="min-h-0 space-y-4 overflow-y-auto pr-1 text-sm">
                <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded border border-border/60 px-3 py-2">
                  <dt class="text-muted-foreground">Author</dt>
                  <dd>{descriptor().author}</dd>
                  <dt class="text-muted-foreground">Version</dt>
                  <dd>{descriptor().version}</dd>
                  <dt class="text-muted-foreground">Bundle</dt>
                  <dd>{bundleHashPrefix(descriptor().bundleHash)}</dd>
                </dl>
                <p class="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive">
                  {pluginConsentSecurityWarning()}
                </p>
                <div class="space-y-2">
                  <p class="text-muted-foreground">Requested permissions</p>
                  <ul class="space-y-1">
                    <For each={descriptor().permissions}>
                      {(permission) => (
                        <li class="rounded border border-border/60 px-3 py-2">{permission}</li>
                      )}
                    </For>
                  </ul>
                </div>
                <Show when={descriptor().networkEndpoints.length > 0}>
                  <div class="space-y-2">
                    <p class="text-muted-foreground">Network access</p>
                    <ul class="space-y-1">
                      <For each={descriptor().networkEndpoints}>
                        {(endpoint) => (
                          <li class="rounded border border-border/60 px-3 py-2">
                            {typeof endpoint.url === "string"
                              ? endpoint.url
                              : "Configured endpoint"}
                          </li>
                        )}
                      </For>
                    </ul>
                  </div>
                </Show>
                <Show
                  when={
                    highRiskConsentDetails(descriptor(), {
                      proxy: options.networkProxyRegistration?.() ?? null,
                    }).length > 0
                  }
                >
                  <div class="space-y-2">
                    <p class="text-muted-foreground">High-risk access</p>
                    <ul class="space-y-1">
                      <For
                        each={highRiskConsentDetails(descriptor(), {
                          proxy: options.networkProxyRegistration?.() ?? null,
                        })}
                      >
                        {(detail) => (
                          <li class="rounded border border-border/60 px-3 py-2">{detail}</li>
                        )}
                      </For>
                    </ul>
                  </div>
                </Show>
                <Show when={error()}>
                  <p class="text-sm text-destructive">{error()}</p>
                </Show>
              </div>
              <DialogFooter>
                <Button
                  variant="outline"
                  disabled={busyApplicationId() === descriptor().applicationId}
                  onClick={() => dismiss(descriptor())}
                >
                  Close
                </Button>
                <Button
                  variant="outline"
                  disabled={
                    busyApplicationId() === descriptor().applicationId ||
                    !canSubmitConsentDecision()
                  }
                  onClick={() => void decide(descriptor(), "deny")}
                >
                  Deny
                </Button>
                <Show when={hasExistingConsentHead(descriptor())}>
                  <Button
                    variant="outline"
                    disabled={
                      busyApplicationId() === descriptor().applicationId ||
                      !canSubmitConsentDecision()
                    }
                    onClick={() => void decide(descriptor(), "revoke")}
                  >
                    Revoke
                  </Button>
                </Show>
                <Button
                  disabled={
                    busyApplicationId() === descriptor().applicationId ||
                    !canSubmitConsentDecision()
                  }
                  onClick={() => void decide(descriptor(), "allow")}
                >
                  Allow
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </Show>
    );
  };

  return { view };
}

export async function listPluginConsentRequired(
  workspaceId: string,
  options: { runtimeApplications?: readonly PluginRuntimeApplicationDescriptor[] } = {},
): Promise<readonly PluginConsentRequiredDescriptor[]> {
  const [serverDescriptors, runtimeDescriptors] = await Promise.all([
    listServerPluginConsentRequired(workspaceId),
    options.runtimeApplications
      ? Promise.resolve(pluginRuntimeApplicationsToConsentCandidates(options.runtimeApplications))
      : listPluginRuntimeConsentCandidates(workspaceId),
  ]);
  const auth = authState();
  const missingLocalPins = auth?.user.id
    ? await pluginConsentDescriptorsMissingLocalPins(runtimeDescriptors, auth.user.id, {
        getConsentPin: getPluginConsentPin,
        getStatePin: getPluginStatePin,
      })
    : [];
  const merged = new Map<string, PluginConsentRequiredDescriptor>();
  for (const descriptor of [...serverDescriptors, ...missingLocalPins]) {
    merged.set(descriptorKey(descriptor), descriptor);
  }
  return Array.from(merged.values());
}

function pluginRuntimeApplicationsToConsentCandidates(
  applications: readonly PluginRuntimeApplicationDescriptor[],
): readonly PluginConsentRequiredDescriptor[] {
  return applications.flatMap((entry) => {
    const applicationScopeKind = stringValue(entry.applicationScopeKind);
    const version = stringValue(entry.version);
    const bundleHash = stringValue(entry.bundleHash);
    const manifestHash = stringValue(entry.manifestHash);
    const resourceManifestHash = stringValue(entry.resourceManifestHash);
    const permissionsHash = stringValue(entry.permissionsHash);
    const endpointHash = stringValue(entry.endpointHash);
    const rendererSlotsHash = stringValue(entry.rendererSlotsHash);
    const documentScopeHash = stringValue(entry.documentScopeHash);
    const approvalEventHash = stringValue(entry.approvalEventHash);
    const signerDeviceId = stringValue(entry.signerDeviceId);
    const signerUserId = stringValue(entry.signerUserId);
    if (
      !applicationScopeKind ||
      !version ||
      !bundleHash ||
      !manifestHash ||
      !resourceManifestHash ||
      !permissionsHash ||
      !endpointHash ||
      !rendererSlotsHash ||
      !documentScopeHash ||
      !approvalEventHash ||
      !signerDeviceId ||
      !signerUserId
    ) {
      return [];
    }

    return [
      {
        pluginId: entry.pluginId,
        packageId: entry.packageId,
        applicationId: entry.applicationId,
        activationId: entry.activationId,
        ownerScopeKind: entry.ownerScopeKind,
        applicationScopeKind,
        workspaceId: entry.workspaceId,
        stateHeadHash: entry.stateHeadHash,
        approvalEventHash,
        consentHeadHash: stringValue(entry.consentHeadHash) || null,
        consentEpoch: typeof entry.consentEpoch === "number" ? entry.consentEpoch : null,
        version,
        bundleHash,
        manifestHash,
        resourceManifestHash,
        permissionsHash,
        endpointHash,
        rendererSlotsHash,
        documentScopeHash,
        signerDeviceId,
        signerUserId,
        documentScope: entry.documentScope
          ? ({ ...entry.documentScope } as Record<string, unknown>)
          : null,
        title: stringValue(entry.title) || entry.pluginId,
        author: stringValue(entry.author) || "Unknown author",
        permissions: entry.permissions ?? [],
        networkEndpoints: (entry.networkEndpoints ?? []) as unknown as readonly Record<
          string,
          unknown
        >[],
        highRiskConsents: entry.highRiskConsents ?? [],
      },
    ];
  });
}

async function listServerPluginConsentRequired(
  workspaceId: string,
): Promise<readonly PluginConsentRequiredDescriptor[]> {
  const result = await guardedPluginRuntimeWorkspaceRequest(workspaceId, () =>
    client.GET("/api/workspaces/{workspace_id}/plugin-runtime/consent-required", {
      params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
    }),
  );
  if (!result) return [];

  const envelope = throwIfError(result) as PluginConsentRequiredEnvelope;

  return (envelope.applications ?? []).flatMap(normalizePluginConsentRequiredDescriptor);
}

async function listPluginRuntimeConsentCandidates(
  workspaceId: string,
): Promise<readonly PluginConsentRequiredDescriptor[]> {
  const result = await guardedPluginRuntimeWorkspaceRequest(workspaceId, () =>
    client.GET("/api/workspaces/{workspace_id}/plugin-runtime", {
      params: withUserRrpParams({ path: { workspace_id: workspaceId } }),
    }),
  );
  if (!result) return [];

  const envelope = throwIfError(result) as PluginConsentRequiredEnvelope;

  return (envelope.applications ?? []).flatMap(normalizePluginConsentRequiredDescriptor);
}

export async function pluginConsentDescriptorsMissingLocalPins(
  descriptors: readonly PluginConsentRequiredDescriptor[],
  userId: string,
  deps: {
    getConsentPin(
      workspaceId: string,
      packageId: string,
      applicationId: string,
      activationId: string,
      userId: string,
    ): Promise<PluginConsentPin | null>;
    getStatePin(
      workspaceId: string,
      packageId: string,
      applicationId: string,
      activationId: string,
    ): Promise<PluginStatePin | null>;
  },
): Promise<readonly PluginConsentRequiredDescriptor[]> {
  const result: PluginConsentRequiredDescriptor[] = [];
  for (const descriptor of descriptors) {
    const [statePin, consentPin] = await Promise.all([
      deps.getStatePin(
        descriptor.workspaceId,
        descriptor.packageId,
        descriptor.applicationId,
        descriptor.activationId,
      ),
      deps.getConsentPin(
        descriptor.workspaceId,
        descriptor.packageId,
        descriptor.applicationId,
        descriptor.activationId,
        userId,
      ),
    ]);
    if (
      !statePin ||
      !consentPin ||
      !localPluginStatePinMatchesDescriptor(descriptor, statePin) ||
      !localPluginConsentPinMatchesDescriptor(descriptor, consentPin, userId)
    ) {
      result.push(descriptor);
    }
  }
  return result;
}

function localPluginStatePinMatchesDescriptor(
  descriptor: PluginConsentRequiredDescriptor,
  statePin: PluginStatePin,
): boolean {
  return (
    statePin.workspaceId === descriptor.workspaceId &&
    statePin.packageId === descriptor.packageId &&
    statePin.applicationId === descriptor.applicationId &&
    statePin.activationId === descriptor.activationId &&
    statePin.latestEventHash === descriptor.stateHeadHash &&
    statePin.bundleHash === descriptor.bundleHash &&
    statePin.approvalEventHash === descriptor.approvalEventHash
  );
}

function localPluginConsentPinMatchesDescriptor(
  descriptor: PluginConsentRequiredDescriptor,
  consentPin: PluginConsentPin,
  userId: string,
): boolean {
  return (
    descriptor.consentHeadHash !== null &&
    descriptor.consentEpoch !== null &&
    consentPin.workspaceId === descriptor.workspaceId &&
    consentPin.packageId === descriptor.packageId &&
    consentPin.applicationId === descriptor.applicationId &&
    consentPin.activationId === descriptor.activationId &&
    consentPin.userId === userId &&
    consentPin.latestEventHash === descriptor.consentHeadHash &&
    consentPin.consentEpoch === descriptor.consentEpoch
  );
}

export async function submitPluginConsentDecision(
  descriptor: PluginConsentRequiredDescriptor,
  decision: PluginConsentSubject["decision"],
  deps: PluginConsentActionDependencies,
): Promise<void> {
  if (decision === "allow") {
    const statePin = await deps.getStatePin(
      descriptor.workspaceId,
      descriptor.packageId,
      descriptor.applicationId,
      descriptor.activationId,
    );
    if (!statePin) {
      throw new Error("plugin_state_pin_required");
    } else if (!localPluginStatePinMatchesDescriptor(descriptor, statePin)) {
      throw new Error("plugin_state_pin_mismatch");
    }
  }

  const consent = buildPluginConsentSubject(descriptor, {
    userId: deps.userId,
    deviceId: deps.deviceId,
    decision,
  });
  const eventHash = pluginConsentEventHash(consent);
  const signed = await deps.sign(consent);
  const body = {
    ...consent,
    event_hash: eventHash,
    hybrid_signature: signed.signature as unknown as StrictJsonValue,
  };
  const response = await deps.appendConsent(body);
  const event = response.consent_event;
  if (!event?.event_hash || event.event_hash !== eventHash) {
    throw new Error("plugin_consent_event_mismatch");
  }

  await deps.saveConsentPin({
    workspaceId: descriptor.workspaceId,
    packageId: descriptor.packageId,
    applicationId: descriptor.applicationId,
    activationId: descriptor.activationId,
    userId: deps.userId,
    consentEpoch: event.consent_epoch ?? consent.consent_epoch,
    latestEventHash: eventHash,
    updatedAtMs: deps.nowMs(),
  });
}

export async function savePluginConsentDescriptorStatePin(
  descriptor: PluginConsentRequiredDescriptor,
  nowMs: number = Date.now(),
  saveStatePin: (pin: PluginStatePin) => Promise<void> = savePluginStatePin,
): Promise<void> {
  await saveStatePin({
    workspaceId: descriptor.workspaceId,
    packageId: descriptor.packageId,
    applicationId: descriptor.applicationId,
    activationId: descriptor.activationId,
    latestEventHash: descriptor.stateHeadHash,
    bundleHash: descriptor.bundleHash,
    approvalEventHash: descriptor.approvalEventHash,
    updatedAtMs: nowMs,
  });
}

export function buildPluginConsentSubject(
  descriptor: PluginConsentRequiredDescriptor,
  params: {
    userId: string;
    deviceId: string;
    decision: PluginConsentSubject["decision"];
  },
): PluginConsentSubject {
  return {
    plugin_id: descriptor.pluginId,
    package_id: descriptor.packageId,
    application_id: descriptor.applicationId,
    activation_id: descriptor.activationId,
    owner_scope_kind: descriptor.ownerScopeKind,
    application_scope_kind: descriptor.applicationScopeKind,
    version: descriptor.version,
    bundle_hash: descriptor.bundleHash,
    manifest_hash: descriptor.manifestHash,
    resource_manifest_hash: descriptor.resourceManifestHash,
    permissions_hash: descriptor.permissionsHash,
    endpoint_hash: descriptor.endpointHash,
    document_scope_hash: descriptor.documentScopeHash,
    signer_device_id: descriptor.signerDeviceId,
    signer_user_id: descriptor.signerUserId,
    user_id: params.userId,
    device_id: params.deviceId,
    workspace_id: descriptor.workspaceId,
    consent_epoch: (descriptor.consentEpoch ?? 0) + 1,
    previous_event_hash: descriptor.consentHeadHash ?? "GENESIS",
    decision: params.decision,
  };
}

function pluginConsentDecisionErrorMessage(error: unknown): string {
  if (
    error instanceof Error &&
    (error.message === "plugin_state_pin_required" || error.message === "plugin_state_pin_mismatch")
  ) {
    return "Plugin approval state is not trusted on this device. Re-apply the plugin from Community Plugins or transfer trust before allowing consent.";
  }
  return "Plugin consent could not be saved.";
}

export function pluginConsentEventHash(consent: PluginConsentSubject): string {
  return blake3Base64Url(canonicalizeStrictBytes(consent));
}

export function highRiskConsentDetails(
  descriptor: PluginConsentRequiredDescriptor,
  options: { proxy?: PluginNetworkProxyRegistration | null } = {},
): readonly string[] {
  const details: string[] = [];
  const highRisk = new Set(descriptor.highRiskConsents);

  if (highRisk.has("plaintext_network_egress")) {
    details.push("Plaintext-capable plugin may send received plaintext to declared endpoints.");
  }
  if (highRisk.has("plaintext_document_write")) {
    details.push(
      "Plaintext-capable plugin may write encrypted document updates whose size, frequency, and timing remain observable.",
    );
  }
  if (highRisk.has("plaintext_cache_storage")) {
    details.push(
      "Plaintext-capable plugin may store derived plaintext data in the encrypted local cache.",
    );
  }
  if (hasWorkspaceExportAuthority(descriptor, highRisk)) {
    details.push("Workspace-wide plaintext scope can be exported to declared network endpoints.");
    details.push(
      `Workspace document source limit: up to ${MAX_WORKSPACE_DOCUMENT_QUERY_DOCUMENTS} documents and ${MAX_WORKSPACE_DOCUMENT_QUERY_BYTES} plaintext bytes per invocation.`,
    );
  }

  for (const endpoint of descriptor.networkEndpoints) {
    const url = stringValue(endpoint.url) || "Configured endpoint";
    const routes = stringList(endpoint.routes);
    const maxRequestBytes = numberValue(endpoint.maxRequestBytes);
    const maxResponseBytes = numberValue(endpoint.maxResponseBytes);
    details.push(
      [
        `Endpoint ${url}`,
        routes.length > 0 ? `routes: ${routes.join(", ")}` : null,
        maxRequestBytes ? `request limit: ${maxRequestBytes} bytes` : null,
        maxResponseBytes ? `response limit: ${maxResponseBytes} bytes` : null,
      ]
        .filter(Boolean)
        .join("; "),
    );
    if (routes.includes("proxy")) {
      details.push(proxyRouteConsentDetail(options.proxy ?? null));
    }
  }

  return Array.from(new Set(details));
}

function hasExistingConsentHead(descriptor: PluginConsentRequiredDescriptor): boolean {
  return descriptor.consentHeadHash !== null && descriptor.consentEpoch !== null;
}

function hasWorkspaceExportAuthority(
  descriptor: PluginConsentRequiredDescriptor,
  highRisk: ReadonlySet<string>,
): boolean {
  return (
    highRisk.has("workspace_network_egress") ||
    (workspaceReadAllowed(descriptor.documentScope) &&
      descriptor.permissions.includes("network:fetch"))
  );
}

export function pluginConsentSecurityWarning(): string {
  return "This plugin can access decrypted data for the displayed scopes. With network fetch or storage writes, it can send or save plaintext to external endpoints or permitted encrypted storage. Plaintext promotion into workspace shared storage is not allowed.";
}

function proxyRouteConsentDetail(proxy: PluginNetworkProxyRegistration | null): string {
  const prefix = proxy
    ? `Proxy route uses ${proxy.label} (${proxy.origin}; ${proxy.scope} scope; id: ${proxy.id}; operator: ${proxy.operatorLabel ?? proxy.label}).`
    : "Proxy route uses the configured proxy operator.";

  return `${prefix} Proxy operator and target endpoint can process target URL, method, request headers/body, response status/headers/body, timing, size, credential use, and plaintext included in the request or response.`;
}

function bundleHashPrefix(bundleHash: string): string {
  return bundleHash.slice(0, 8);
}

async function appendPluginConsentEvent(
  descriptor: PluginConsentRequiredDescriptor,
  body: Record<string, StrictJsonValue>,
): Promise<ConsentEventResponse> {
  return throwIfError(
    await client.POST(
      "/api/workspaces/{workspace_id}/plugin-applications/{application_id}/consent-events",
      {
        params: withUserRrpParams({
          path: {
            workspace_id: descriptor.workspaceId,
            application_id: descriptor.applicationId,
          },
        }),
        body: body as components["schemas"]["PluginConsentEventRequest"],
      },
    ),
  ) as ConsentEventResponse;
}

export function normalizePluginConsentRequiredDescriptor(
  entry: PluginConsentRequiredEntry,
): readonly PluginConsentRequiredDescriptor[] {
  const pluginId = stringValue(entry.plugin_id);
  const packageId = stringValue(entry.package_id);
  const applicationId = stringValue(entry.application_id);
  const activationId = stringValue(entry.activation_id);
  const ownerScopeKind = stringValue(entry.owner_scope_kind);
  const applicationScopeKind = stringValue(entry.application_scope_kind);
  const workspaceId = stringValue(entry.workspace_id);
  const stateHeadHash = stringValue(entry.state_head_hash);
  const approvalEventHash = stringValue(entry.approval_event_hash);
  const version = stringValue(entry.version);
  const bundleHash = stringValue(entry.bundle_hash);
  const manifestHash = stringValue(entry.manifest_hash);
  const resourceManifestHash = stringValue(entry.resource_manifest_hash);
  const permissionsHash = stringValue(entry.permissions_hash);
  const endpointHash = stringValue(entry.endpoint_hash);
  const rendererSlotsHash = stringValue(entry.renderer_slots_hash);
  const documentScopeHash = stringValue(entry.document_scope_hash);
  const signerDeviceId = stringValue(entry.signer_device_id);
  const signerUserId = stringValue(entry.signer_user_id);
  if (
    !pluginId ||
    !packageId ||
    !applicationId ||
    !activationId ||
    !ownerScopeKind ||
    !applicationScopeKind ||
    !workspaceId ||
    !stateHeadHash ||
    !approvalEventHash ||
    !version ||
    !bundleHash ||
    !manifestHash ||
    !resourceManifestHash ||
    !permissionsHash ||
    !endpointHash ||
    !rendererSlotsHash ||
    !documentScopeHash ||
    !signerDeviceId ||
    !signerUserId
  ) {
    return [];
  }

  const rawPermissions = strictJsonArray(entry.permissions);
  const rawNetworkEndpoints = strictJsonArray(entry.network_endpoints);
  const rawRendererSlots = strictJsonArray(entry.renderer_slots);
  const rawDocumentScopes = strictJsonArray(entry.document_scopes);
  const authority = derivePluginManifestAuthority({
    permissions: rawPermissions,
    network: { endpoints: rawNetworkEndpoints },
    rendererSlots: rawRendererSlots,
    documentScopes: rawDocumentScopes,
  });
  try {
    assertPluginManifestAuthorityHashes(authority, {
      permissionsHash,
      endpointHash,
      rendererSlotsHash,
      documentScopeHash,
    });
  } catch {
    return [];
  }

  return [
    {
      pluginId,
      packageId,
      applicationId,
      activationId,
      ownerScopeKind,
      applicationScopeKind,
      workspaceId,
      stateHeadHash,
      approvalEventHash,
      consentHeadHash: stringValue(entry.consent_head_hash) || null,
      consentEpoch: typeof entry.consent_epoch === "number" ? entry.consent_epoch : null,
      version,
      bundleHash,
      manifestHash,
      resourceManifestHash,
      permissionsHash,
      endpointHash,
      rendererSlotsHash,
      documentScopeHash,
      signerDeviceId,
      signerUserId,
      documentScope: authority.documentScope ? { ...authority.documentScope } : null,
      title: stringValue(entry.title) || pluginId,
      author: stringValue(entry.author) || "Unknown author",
      permissions: authority.permissions,
      networkEndpoints: authority.networkEndpoints as unknown as readonly Record<string, unknown>[],
      highRiskConsents: authority.highRiskConsents,
    },
  ];
}

function descriptorKey(descriptor: PluginConsentRequiredDescriptor): string {
  return `${descriptor.packageId}:${descriptor.applicationId}:${descriptor.activationId}:${descriptor.bundleHash}`;
}

function stringValue(value: unknown): string {
  return typeof value === "string" && value.trim() !== "" ? value : "";
}

function stringList(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function strictJsonArray(value: unknown): StrictJsonValue[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isStrictJsonValue);
}

function isStrictJsonValue(value: unknown): value is StrictJsonValue {
  if (
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
  ) {
    return true;
  }
  if (Array.isArray(value)) return value.every(isStrictJsonValue);
  if (isRecord(value)) return Object.values(value).every(isStrictJsonValue);
  return false;
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function workspaceReadAllowed(scope: Record<string, unknown> | null): boolean {
  if (!scope) return false;
  if (scope.workspaceReadAllowed === true) return true;
  const entries = Array.isArray(scope.documentScopes) ? scope.documentScopes : [];
  return entries.some((entry) => isRecord(entry) && entry.kind === "workspace");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
