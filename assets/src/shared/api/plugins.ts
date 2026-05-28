import { client, throwIfError, withUserPopParams } from "./core";
import type { components } from "./schema";

type ApiResult = { data?: unknown; error?: unknown; response: Response };
const apiPost = client.POST as unknown as (
  path: string,
  options: Record<string, unknown>,
) => Promise<ApiResult>;
const apiDelete = client.DELETE as unknown as (
  path: string,
  options: Record<string, unknown>,
) => Promise<ApiResult>;

export type PluginOwnerScopeKind = "user" | "workspace";
export type PluginWorkspacePolicyResult = "allowed" | "denied" | "needs_admin_review";

export interface PluginPackageInfo {
  id: string;
  plugin_id: string;
  version: string;
  owner_scope_kind: PluginOwnerScopeKind;
  owner_workspace_id?: string | null;
  owner_user_id?: string | null;
  current_bundle_id?: string | null;
  state_head_hash?: string | null;
  bundle_hash?: string | null;
  resource_manifest_hash?: string | null;
}

export interface PluginApplicationInfo {
  id: string;
  package_id: string;
  plugin_id: string;
  workspace_id: string;
  application_scope_kind: string;
  application_mode: string;
  workspace_policy_result: PluginWorkspacePolicyResult;
  enabled: boolean;
  consent_epoch: number;
  state_head_hash?: string | null;
  current_bundle_id?: string | null;
  network_endpoints?: readonly Record<string, unknown>[];
  deleted_at?: string | null;
}

export interface PluginActivationInfo {
  id: string;
  application_id: string;
  workspace_id?: string | null;
  package_id?: string | null;
  plugin_id?: string | null;
  bundle_hash?: string | null;
  user_id: string;
  device_id?: string | null;
  activation_scope_kind: string;
  enabled: boolean;
  deleted_at?: string | null;
}

export interface PluginCapabilitySummary {
  permissions?: readonly unknown[];
  network_endpoints?: readonly unknown[];
  renderer_slots?: readonly unknown[];
  document_scopes?: readonly unknown[];
}

export interface PluginScopeSummary {
  supported_owner_scopes?: readonly PluginOwnerScopeKind[];
  default_owner_scope?: PluginOwnerScopeKind | null;
  workspace_application?: "none" | "optional" | "required" | string | null;
}

export interface PluginApprovalSummary {
  actor?: Record<string, unknown>;
  subject?: Record<string, unknown>;
  approval_event_hash?: string;
  approval_epoch?: number;
  previous_approval_event_hash?: string;
  created_at_ms?: number;
}

export interface PluginBundleCandidateInfo {
  id: string;
  plugin_id?: string | null;
  version?: string | null;
  owner_scope_kind: PluginOwnerScopeKind;
  owner_workspace_id?: string | null;
  owner_user_id?: string | null;
  workspace_id?: string | null;
  source_kind: "remote_https_url" | "local_upload" | string;
  source_url?: string | null;
  source_url_hash?: string | null;
  archive_hash?: string | null;
  validation_status?: string | null;
  validation_errors?: unknown;
  bundle_hash?: string | null;
  manifest_hash?: string | null;
  main_js_hash?: string | null;
  styles_css_hash?: string | null;
  resource_manifest_hash?: string | null;
  resource_manifest?: unknown;
  permissions_hash?: string | null;
  endpoint_hash?: string | null;
  renderer_slots_hash?: string | null;
  document_scope_hash?: string | null;
  capability_summary?: PluginCapabilitySummary;
  scope_summary?: PluginScopeSummary;
  approval_summary?: PluginApprovalSummary | null;
}

export interface PluginCandidateSourceInput {
  ownerScopeKind?: PluginOwnerScopeKind;
  workspaceId?: string | null;
  sourceKind: "remote_https_url" | "local_upload";
  sourceUrl?: string;
  archiveBase64?: string;
}

export interface PluginApprovalPayload {
  approval_event_hash: string;
  approval_epoch: number;
  previous_approval_event_hash: string;
  created_at_ms: number;
  hybrid_signature: unknown;
}

interface ConsentEventEnvelope {
  consent_event?: {
    event_hash?: string;
    decision?: string;
    consent_epoch?: number;
  };
}

interface PackagesEnvelope {
  packages?: readonly PluginPackageInfo[];
}

interface ApplicationsEnvelope {
  plugins?: readonly PluginApplicationInfo[];
}

interface CandidateEnvelope {
  candidate?: PluginBundleCandidateInfo;
}

interface PackageEnvelope {
  package?: PluginPackageInfo;
}

export interface PluginPromotionResult {
  package: PluginPackageInfo;
  application?: PluginApplicationInfo;
  activation?: PluginActivationInfo;
}

interface ApplicationEnvelope {
  application?: PluginApplicationInfo;
  activation?: PluginActivationInfo;
  plugin?: PluginApplicationInfo;
}

interface ActivationsEnvelope {
  activations?: readonly PluginActivationInfo[];
}

function candidateBody(input: PluginCandidateSourceInput): Record<string, unknown> {
  const body: Record<string, unknown> = { source_kind: input.sourceKind };
  if (input.sourceKind === "remote_https_url") body.source_url = input.sourceUrl ?? "";
  if (input.sourceKind === "local_upload") body.archive_base64 = input.archiveBase64 ?? "";
  return body;
}

export async function arrayBufferToBase64(buffer: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export const pluginsApi = {
  listUserPackages: async (): Promise<readonly PluginPackageInfo[]> => {
    const envelope = throwIfError(
      await client.GET("/api/plugin-packages", { params: withUserPopParams() }),
    ) as PackagesEnvelope;
    return envelope.packages ?? [];
  },

  listWorkspacePackages: async (workspaceId: string): Promise<readonly PluginPackageInfo[]> => {
    const envelope = throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/plugin-packages", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ) as PackagesEnvelope;
    return envelope.packages ?? [];
  },

  listApplications: async (workspaceId: string): Promise<readonly PluginApplicationInfo[]> => {
    const envelope = throwIfError(
      await client.GET("/api/workspaces/{workspace_id}/plugin-applications", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
      }),
    ) as ApplicationsEnvelope;
    return envelope.plugins ?? [];
  },

  listActivations: async (): Promise<readonly PluginActivationInfo[]> => {
    const envelope = throwIfError(
      await client.GET("/api/plugin-activations", { params: withUserPopParams() }),
    ) as ActivationsEnvelope;
    return envelope.activations ?? [];
  },

  createCandidate: async (
    input: PluginCandidateSourceInput,
  ): Promise<PluginBundleCandidateInfo> => {
    const body = candidateBody(input);

    if (!input.ownerScopeKind) {
      if (input.workspaceId) body.workspace_id = input.workspaceId;

      const envelope = throwIfError(
        await apiPost("/api/plugin-candidates", {
          params: withUserPopParams(),
          body,
        }),
      ) as CandidateEnvelope;

      if (!envelope.candidate) throw new Error("plugin_candidate_missing");
      return envelope.candidate;
    }

    const envelope =
      input.ownerScopeKind === "user"
        ? (throwIfError(
            await apiPost("/api/plugin-packages", {
              params: withUserPopParams(),
              body,
            }),
          ) as CandidateEnvelope)
        : (throwIfError(
            await apiPost("/api/workspaces/{workspace_id}/plugin-packages", {
              params: withUserPopParams({
                path: { workspace_id: input.workspaceId ?? "" },
              }),
              body,
            }),
          ) as CandidateEnvelope);

    if (!envelope.candidate) throw new Error("plugin_candidate_missing");
    return envelope.candidate;
  },

  showCandidate: async (
    ownerScopeKind: PluginOwnerScopeKind,
    candidateId: string,
    workspaceId?: string | null,
  ): Promise<PluginBundleCandidateInfo> => {
    void ownerScopeKind;
    void workspaceId;
    const envelope = throwIfError(
      await client.GET("/api/plugin-candidates/{candidate_id}", {
        params: withUserPopParams({ path: { candidate_id: candidateId } }),
      }),
    ) as CandidateEnvelope;

    if (!envelope.candidate) throw new Error("plugin_candidate_missing");
    return envelope.candidate;
  },

  promoteCandidate: async (
    ownerScopeKind: PluginOwnerScopeKind,
    candidateId: string,
    approval: PluginApprovalPayload,
    workspaceId?: string | null,
  ): Promise<PluginPromotionResult> => {
    void ownerScopeKind;
    const envelope = throwIfError(
      await apiPost("/api/plugin-candidates/{candidate_id}/approval", {
        params: withUserPopParams({ path: { candidate_id: candidateId } }),
        body: {
          ...approval,
          ...(workspaceId ? { workspace_id: workspaceId } : {}),
        },
      }),
    ) as PackageEnvelope;

    if (!envelope.package) throw new Error("plugin_package_missing");
    return {
      package: envelope.package,
      application: (envelope as ApplicationEnvelope).application,
      activation: (envelope as ApplicationEnvelope).activation,
    };
  },

  applyPackage: async (
    workspaceId: string,
    packageId: string,
  ): Promise<{ application: PluginApplicationInfo; activation?: PluginActivationInfo }> => {
    const envelope = throwIfError(
      await client.POST("/api/workspaces/{workspace_id}/plugin-applications", {
        params: withUserPopParams({ path: { workspace_id: workspaceId } }),
        body: {
          package_id: packageId,
        } satisfies components["schemas"]["PluginApplicationApplyRequest"],
      }),
    ) as ApplicationEnvelope;
    if (!envelope.application) throw new Error("plugin_application_missing");
    return { application: envelope.application, activation: envelope.activation };
  },

  updateApplication: async (
    workspaceId: string,
    applicationId: string,
    body: components["schemas"]["PluginApplicationUpdateRequest"],
  ): Promise<PluginApplicationInfo> => {
    const envelope = throwIfError(
      await client.PATCH("/api/workspaces/{workspace_id}/plugin-applications/{application_id}", {
        params: withUserPopParams({
          path: { workspace_id: workspaceId, application_id: applicationId },
        }),
        body,
      }),
    ) as ApplicationEnvelope;
    const plugin = envelope.plugin ?? envelope.application;
    if (!plugin) throw new Error("plugin_application_missing");
    return plugin;
  },

  deleteApplication: async (
    workspaceId: string,
    applicationId: string,
  ): Promise<PluginApplicationInfo> => {
    const envelope = throwIfError(
      await client.DELETE("/api/workspaces/{workspace_id}/plugin-applications/{application_id}", {
        params: withUserPopParams({
          path: { workspace_id: workspaceId, application_id: applicationId },
        }),
      }),
    ) as ApplicationEnvelope;
    const plugin = envelope.plugin ?? envelope.application;
    if (!plugin) throw new Error("plugin_application_missing");
    return plugin;
  },

  updateActivation: async (
    activationId: string,
    body: components["schemas"]["PluginActivationUpdateRequest"],
  ): Promise<PluginActivationInfo> => {
    const envelope = throwIfError(
      await client.PATCH("/api/plugin-activations/{activation_id}", {
        params: withUserPopParams({ path: { activation_id: activationId } }),
        body,
      }),
    ) as ApplicationEnvelope;
    if (!envelope.activation) throw new Error("plugin_activation_missing");
    return envelope.activation;
  },

  deleteActivation: async (activationId: string): Promise<PluginActivationInfo> => {
    const envelope = throwIfError(
      await apiDelete("/api/plugin-activations/{activation_id}", {
        params: withUserPopParams({ path: { activation_id: activationId } }),
      }),
    ) as ApplicationEnvelope;
    if (!envelope.activation) throw new Error("plugin_activation_missing");
    return envelope.activation;
  },

  appendConsentEvent: async (
    workspaceId: string,
    applicationId: string,
    body: components["schemas"]["PluginConsentEventRequest"],
  ): Promise<ConsentEventEnvelope> => {
    return throwIfError(
      await client.POST(
        "/api/workspaces/{workspace_id}/plugin-applications/{application_id}/consent-events",
        {
          params: withUserPopParams({
            path: { workspace_id: workspaceId, application_id: applicationId },
          }),
          body,
        },
      ),
    ) as ConsentEventEnvelope;
  },
};
