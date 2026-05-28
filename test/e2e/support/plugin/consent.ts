import { type Page } from "@playwright/test";
import { E2E_DELAYS } from "../timeouts";
import { pluginRuntimeDiagnostic } from "./diagnostics";
import {
  pluginRuntimeApplicationLoaded,
  type PluginRuntimeWaitOptions,
} from "./runtime";
import {
  type ConsentDescriptor,
  EMPTY_SEMANTIC_HASH,
} from "./types";

export async function allowPluginConsentIfPresent(
  page: Page,
  timeout = 30_000,
  closeTimeout = Math.max(timeout, 60_000),
): Promise<void> {
  const dialog = page.getByRole("dialog", { name: "Plugin Consent" });
  let lastError: unknown;
  if (!(await dialog.isVisible({ timeout }).catch(() => false))) {
    return;
  }
  const allowButton = dialog.getByRole("button", { name: "Allow" });
  const deadline = Date.now() + closeTimeout;
  let clicked = false;
  while (Date.now() < deadline) {
    if (!(await dialog.isVisible({ timeout: 500 }).catch(() => false))) {
      return;
    }
    const remaining = Math.max(250, deadline - Date.now());
    if (await allowButton.isEnabled({ timeout: Math.min(2_000, remaining) }).catch(() => false)) {
      clicked = true;
      await allowButton.click({ timeout: Math.min(10_000, remaining) }).catch((clickError) => {
        lastError = clickError;
      });
      if (
        await dialog
          .waitFor({ state: "hidden", timeout: Math.min(10_000, Math.max(250, deadline - Date.now())) })
          .then(() => true)
          .catch(() => false)
      ) {
        return;
      }
    } else if (!clicked) {
      await allowButton.focus().catch((focusError) => {
        lastError = focusError;
      });
      await page.keyboard.press("Enter").catch((keyboardError) => {
        lastError = keyboardError;
      });
      if (
        await dialog
          .waitFor({ state: "hidden", timeout: Math.min(2_000, Math.max(250, deadline - Date.now())) })
          .then(() => true)
          .catch(() => false)
      ) {
        return;
      }
    }
    await page.waitForTimeout(E2E_DELAYS.poll);
  }
  const statePins = await pluginStatePinDiagnostic(page);
  const buttonDiagnostic = await allowButton
    .evaluate((node) => ({
      tagName: node.tagName,
      disabled: node instanceof HTMLButtonElement ? node.disabled : null,
      ariaDisabled: node.getAttribute("aria-disabled"),
      className: node instanceof HTMLElement ? node.className : "",
      textContent: node.textContent,
    }))
    .catch((error) => ({ error: String(error) }));
  throw new Error(
    `Plugin consent dialog did not close after Allow:\n${await dialog.textContent()}\nPlugin state pins:\n${statePins}\nAllow button:\n${JSON.stringify(
      buttonDiagnostic,
    )}\nClicked:${clicked}\n${String(lastError ?? "")}`,
  );
}

export async function waitForPluginRuntimeApplicationWithConsent(
  page: Page,
  pluginId: string,
  options: PluginRuntimeWaitOptions,
): Promise<void> {
  const deadline = Date.now() + options.timeout;
  let lastConsentError: unknown;
  while (Date.now() < deadline) {
    await allowPluginConsentIfPresent(
      page,
      1_000,
      Math.min(120_000, Math.max(1_000, deadline - Date.now())),
    ).catch((error) => {
      lastConsentError = error;
    });
    if (await pluginRuntimeApplicationLoaded(page, pluginId)) return;
    await page.waitForTimeout(E2E_DELAYS.uiSettle);
  }

  const diagnostic = await pluginRuntimeDiagnostic(page);
  const extraDiagnostic = options.extraDiagnostic ? await options.extraDiagnostic() : "";
  throw new Error(
    `${options.message}: ${diagnostic}${extraDiagnostic ? `\n${extraDiagnostic}` : ""}${
      lastConsentError ? `\nLast consent error:\n${String(lastConsentError)}` : ""
    }`,
  );
}

export async function pluginStatePinDiagnostic(page: Page): Promise<string> {
  return page
    .evaluate(async () => {
      return await new Promise<string>((resolve) => {
        const request = indexedDB.open("refmd-trust");
        request.onerror = () => resolve(`open_error:${String(request.error?.message ?? request.error)}`);
        request.onsuccess = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains("plugin-state-pins")) {
            db.close();
            resolve("store_missing");
            return;
          }
          const tx = db.transaction("plugin-state-pins", "readonly");
          const getAll = tx.objectStore("plugin-state-pins").getAll();
          getAll.onerror = () =>
            resolve(`get_all_error:${String(getAll.error?.message ?? getAll.error)}`);
          getAll.onsuccess = () => resolve(JSON.stringify(getAll.result));
          tx.oncomplete = () => db.close();
        };
      });
    })
    .catch((error) => `diagnostic_error:${String(error)}`);
}

export async function closePluginConsentIfPresent(page: Page, timeout = 30_000): Promise<void> {
  const dialog = page.getByRole("dialog", { name: "Plugin Consent" });
  if (!(await dialog.isVisible({ timeout }).catch(() => false))) {
    return;
  }
  const dismissButton = dialog.getByRole("button", { name: "Close" });
  if (await dismissButton.isVisible({ timeout: 1_000 }).catch(() => false)) {
    await dismissButton.click({ timeout: 10_000 });
    if (await dialog.waitFor({ state: "hidden", timeout: 10_000 }).then(() => true).catch(() => false)) {
      return;
    }
  }
  const closeButton = dialog.locator('[data-slot="dialog-close"]').last();
  if (await closeButton.isVisible({ timeout: 1_000 }).catch(() => false)) {
    await closeButton.click({ timeout: 10_000 });
    if (await dialog.waitFor({ state: "hidden", timeout: 10_000 }).then(() => true).catch(() => false)) {
      return;
    }
  }
  await page.keyboard.press("Escape").catch(() => undefined);
  if (await dialog.waitFor({ state: "hidden", timeout: 10_000 }).then(() => true).catch(() => false)) {
    return;
  }
  throw new Error(
    `Plugin consent dialog could not be dismissed without recording a deny decision:\n${await dialog.textContent()}\n${await pluginRuntimeDiagnostic(page)}`,
  );
}

export function consentDescriptor(workspaceId: string, suffix: string): ConsentDescriptor {
  return {
    plugin_id: `e2e.plugin.${suffix}`,
    package_id: `package-${suffix}`,
    application_id: `00000000-0000-4000-8000-0000000000${
      suffix === "one" ? "01" : "02"
    }`,
    activation_id: `activation-${suffix}`,
    capability_grant_id: `capability-${suffix}`,
    owner_scope_kind: "user",
    application_scope_kind: "workspace",
    workspace_id: workspaceId,
    state_head_hash: `state-head-${suffix}`,
    approval_event_hash: `approval-event-${suffix}`,
    consent_head_hash: null,
    consent_epoch: null,
    version: "1.0.0",
    bundle_hash: EMPTY_SEMANTIC_HASH,
    manifest_hash: EMPTY_SEMANTIC_HASH,
    resource_manifest_hash: EMPTY_SEMANTIC_HASH,
    permissions_hash: EMPTY_SEMANTIC_HASH,
    endpoint_hash: EMPTY_SEMANTIC_HASH,
    renderer_slots_hash: EMPTY_SEMANTIC_HASH,
    document_scope_hash: EMPTY_SEMANTIC_HASH,
    signer_user_id: `approval-user-${suffix}`,
    signer_device_id: `approval-device-${suffix}`,
    title: `E2E Consent Plugin ${suffix}`,
    author: "E2E",
    permissions: [],
    network_endpoints: [],
    renderer_slots: [],
    document_scopes: [],
    high_risk_consents: [],
  };
}

export async function savePluginStatePin(page: Page, descriptor: ConsentDescriptor): Promise<void> {
  await page.evaluate(
    (pin) => {
      const request = indexedDB.open("refmd-trust", 3);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("plugin-state-pins")) {
          db.createObjectStore("plugin-state-pins", {
            keyPath: ["workspaceId", "packageId", "applicationId", "activationId"],
          });
        }
        if (!db.objectStoreNames.contains("plugin-consent-pins")) {
          db.createObjectStore("plugin-consent-pins", {
            keyPath: ["workspaceId", "packageId", "applicationId", "activationId", "userId"],
          });
        }
        if (!db.objectStoreNames.contains("tofu-entries")) {
          const store = db.createObjectStore("tofu-entries", {
            keyPath: ["userId", "deviceId"],
          });
          store.createIndex("by-user", "userId", { unique: false });
        }
      };
      return new Promise<void>((resolve, reject) => {
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const db = request.result;
          const tx = db.transaction("plugin-state-pins", "readwrite");
          tx.objectStore("plugin-state-pins").put(pin);
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => {
            db.close();
            reject(tx.error);
          };
        };
      });
    },
    {
      workspaceId: descriptor.workspace_id,
      packageId: descriptor.package_id,
      applicationId: descriptor.application_id,
      activationId: descriptor.activation_id,
      latestEventHash: descriptor.state_head_hash,
      bundleHash: descriptor.bundle_hash,
      approvalEventHash: descriptor.approval_event_hash,
      updatedAtMs: Date.now(),
    },
  );
}
