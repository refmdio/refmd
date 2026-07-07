import { describe, expect, it } from "vite-plus/test";
import {
  PluginExecutionPolicyError,
  assertPluginExecutionPlacement,
  assertThirdPartyPluginSandboxTarget,
  assertTrustedCoreWorkerDelegation,
  type PluginExecutionTarget,
  type TrustedCoreWorkerDelegation,
} from "./execution-policy";

const forbiddenThirdPartyTargets: PluginExecutionTarget[] = [
  "app_main_realm",
  "parent_dedicated_worker",
  "parent_shared_worker",
  "parent_service_worker",
];

const safeDelegation: TrustedCoreWorkerDelegation = {
  workerCodeTrust: "refmd_core",
  inputBoundary: "host_limited",
  outputBoundary: "host_validated",
  passesPluginCode: false,
  exposesNetworkAuthority: false,
  exposesIndexedDb: false,
  exposesCacheStorage: false,
  allowsServiceWorkerRegistration: false,
  exposesAppOriginStorage: false,
  exposesCryptoWorker: false,
};

describe("plugin execution placement policy", () => {
  it("allows third-party plugin code only in the sandbox iframe by default", () => {
    expect(() => assertThirdPartyPluginSandboxTarget("sandbox_iframe")).not.toThrow();
    expect(() => assertThirdPartyPluginSandboxTarget("trusted_core_worker")).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "trusted_core_worker_delegation_required",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    for (const target of forbiddenThirdPartyTargets) {
      expect(() => assertThirdPartyPluginSandboxTarget(target)).toThrow(
        expect.objectContaining({
          name: "PluginExecutionPolicyError",
          code: "third_party_plugin_worker_forbidden",
        } satisfies Partial<PluginExecutionPolicyError>),
      );
    }
  });

  it("keeps RefMD core code outside the third-party placement restriction", () => {
    for (const target of forbiddenThirdPartyTargets) {
      expect(() =>
        assertPluginExecutionPlacement({ codeTrust: "refmd_core", target }),
      ).not.toThrow();
    }
  });

  it("allows trusted core worker delegation only for Host-limited inputs and core worker code", () => {
    expect(() =>
      assertPluginExecutionPlacement(
        { codeTrust: "third_party", target: "trusted_core_worker" },
        safeDelegation,
      ),
    ).not.toThrow();
  });

  it("rejects trusted core worker delegation without core worker code and bounded IO", () => {
    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        workerCodeTrust: "third_party" as never,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "untrusted_worker_code_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        inputBoundary: "plugin_raw" as never,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "unbounded_worker_input_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        outputBoundary: "plugin_raw" as never,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "unvalidated_worker_output_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );
  });

  it("rejects trusted core worker delegation when plugin code would enter the worker", () => {
    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        passesPluginCode: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "plugin_code_delegation_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );
  });

  it("rejects trusted core worker delegation that exposes app-origin storage or Crypto Worker", () => {
    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        exposesAppOriginStorage: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "app_origin_storage_exposure_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        exposesIndexedDb: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "worker_indexeddb_exposure_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        exposesCacheStorage: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "worker_cache_storage_exposure_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        exposesCryptoWorker: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "crypto_worker_exposure_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );
  });

  it("rejects trusted core worker delegation that exposes network or Service Worker authority", () => {
    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        exposesNetworkAuthority: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "worker_network_authority_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );

    expect(() =>
      assertTrustedCoreWorkerDelegation({
        ...safeDelegation,
        allowsServiceWorkerRegistration: true,
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "worker_service_worker_registration_forbidden",
      } satisfies Partial<PluginExecutionPolicyError>),
    );
  });

  it("requires explicit delegation metadata for trusted core worker use", () => {
    expect(() =>
      assertPluginExecutionPlacement({ codeTrust: "third_party", target: "trusted_core_worker" }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginExecutionPolicyError",
        code: "trusted_core_worker_delegation_required",
      } satisfies Partial<PluginExecutionPolicyError>),
    );
  });
});
