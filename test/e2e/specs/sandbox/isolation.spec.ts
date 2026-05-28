import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { openDocument } from "../../support/documents";
import { waitForPluginRuntimeApplicationWithConsent } from "../../support/plugin/consent";
import { createDocument } from "../../support/plugin/documents";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  assertServedSandboxDocumentResponses,
  PLUGIN_SANDBOX_ISOLATION_FIXTURE,
  PLUGIN_SANDBOX_ISOLATION_PLUGIN_ID,
  watchRealPluginSandboxIsolation,
} from "../../support/sandbox/isolation";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("sandbox document isolation requires every check to pass through the served runtime", async ({
  page,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  await page.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });

  await registerAccount(page);
  const isolation = await watchRealPluginSandboxIsolation(page);

  try {
    await installPluginFromSettings(page, {
      fixtureName: PLUGIN_SANDBOX_ISOLATION_FIXTURE,
      pluginId: PLUGIN_SANDBOX_ISOLATION_PLUGIN_ID,
    });
    await createDocument(page, "Strict Sandbox Isolation");
    await openDocument(page, "Strict Sandbox Isolation");
    await waitForPluginRuntimeApplicationWithConsent(page, PLUGIN_SANDBOX_ISOLATION_PLUGIN_ID, {
      timeout: 180_000,
      message: "isolation demo plugin runtime application was not loaded under strict CSP",
      extraDiagnostic: () => isolation.diagnostic(),
    });

    const observation = await isolation.result();
    const diagnostic = JSON.stringify(observation, null, 2);

    expect(assertServedSandboxDocumentResponses(observation.documents), diagnostic).toEqual([]);
    expect(observation.results, diagnostic).toEqual({
      download: true,
      popup: true,
      formSubmit: true,
      sandboxLocalStorageAccess: true,
      sandboxIndexedDbAccess: true,
      sandboxCacheAccess: true,
      parentLocalStorageAccess: true,
      parentCryptoWorkerAccess: true,
      pluginIframeFetch: true,
      appOriginSubresourceExfil: true,
    });
    expect(observation.requests, diagnostic).toEqual([]);
    expect(observation.downloaded, diagnostic).toBe(false);
    expect(observation.popupOpened, diagnostic).toBe(false);
    expect(observation.unexpectedConsoleErrors, diagnostic).toEqual([]);
  } finally {
    await isolation.stop();
  }
});
