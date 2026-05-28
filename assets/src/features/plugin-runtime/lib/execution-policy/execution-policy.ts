export type PluginCodeTrust = "refmd_core" | "third_party";

export type PluginExecutionTarget =
  | "sandbox_iframe"
  | "app_main_realm"
  | "parent_dedicated_worker"
  | "parent_shared_worker"
  | "parent_service_worker"
  | "trusted_core_worker";

export interface PluginExecutionPlacement {
  codeTrust: PluginCodeTrust;
  target: PluginExecutionTarget;
}

export interface TrustedCoreWorkerDelegation {
  workerCodeTrust: "refmd_core";
  inputBoundary: "host_limited";
  outputBoundary: "host_validated";
  passesPluginCode: boolean;
  exposesNetworkAuthority: boolean;
  exposesIndexedDb: boolean;
  exposesCacheStorage: boolean;
  allowsServiceWorkerRegistration: boolean;
  exposesAppOriginStorage: boolean;
  exposesCryptoWorker: boolean;
}

export class PluginExecutionPolicyError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PluginExecutionPolicyError";
    this.code = code;
  }
}

export function assertPluginExecutionPlacement(
  placement: PluginExecutionPlacement,
  delegation?: TrustedCoreWorkerDelegation,
): void {
  if (placement.codeTrust === "refmd_core") return;

  if (placement.target === "sandbox_iframe") return;

  if (placement.target === "trusted_core_worker") {
    assertTrustedCoreWorkerDelegation(delegation);
    return;
  }

  throw new PluginExecutionPolicyError(
    "third_party_plugin_worker_forbidden",
    `third-party plugin code must not execute in ${placement.target}`,
  );
}

export function assertThirdPartyPluginSandboxTarget(target: PluginExecutionTarget): void {
  assertPluginExecutionPlacement({ codeTrust: "third_party", target });
}

export function assertTrustedCoreWorkerDelegation(
  delegation: TrustedCoreWorkerDelegation | undefined,
): void {
  if (!delegation) {
    throw new PluginExecutionPolicyError(
      "trusted_core_worker_delegation_required",
      "trusted core worker delegation requires an explicit limited-input boundary",
    );
  }

  if (delegation.workerCodeTrust !== "refmd_core") {
    throw new PluginExecutionPolicyError(
      "untrusted_worker_code_forbidden",
      "third-party plugin code cannot be supplied as trusted core worker code",
    );
  }

  if (delegation.inputBoundary !== "host_limited") {
    throw new PluginExecutionPolicyError(
      "unbounded_worker_input_forbidden",
      "trusted core worker delegation must use Host-limited input",
    );
  }

  if (delegation.outputBoundary !== "host_validated") {
    throw new PluginExecutionPolicyError(
      "unvalidated_worker_output_forbidden",
      "trusted core worker delegation must return through Host-validated output",
    );
  }

  if (delegation.passesPluginCode) {
    throw new PluginExecutionPolicyError(
      "plugin_code_delegation_forbidden",
      "trusted core worker delegation must not receive plugin code",
    );
  }

  if (delegation.exposesNetworkAuthority) {
    throw new PluginExecutionPolicyError(
      "worker_network_authority_forbidden",
      "trusted core worker delegation must not expose app-origin network authority",
    );
  }

  if (delegation.exposesIndexedDb) {
    throw new PluginExecutionPolicyError(
      "worker_indexeddb_exposure_forbidden",
      "trusted core worker delegation must not expose app-origin IndexedDB",
    );
  }

  if (delegation.exposesCacheStorage) {
    throw new PluginExecutionPolicyError(
      "worker_cache_storage_exposure_forbidden",
      "trusted core worker delegation must not expose app-origin Cache Storage",
    );
  }

  if (delegation.allowsServiceWorkerRegistration) {
    throw new PluginExecutionPolicyError(
      "worker_service_worker_registration_forbidden",
      "trusted core worker delegation must not allow Service Worker registration",
    );
  }

  if (delegation.exposesAppOriginStorage) {
    throw new PluginExecutionPolicyError(
      "app_origin_storage_exposure_forbidden",
      "trusted core worker delegation must not expose app-origin storage",
    );
  }

  if (delegation.exposesCryptoWorker) {
    throw new PluginExecutionPolicyError(
      "crypto_worker_exposure_forbidden",
      "trusted core worker delegation must not expose Crypto Worker access",
    );
  }
}
