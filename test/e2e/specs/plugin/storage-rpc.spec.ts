import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { waitForPluginRuntimeApplicationWithConsent } from "../../support/plugin/consent";
import {
  pluginRuntimeDiagnostic,
  watchPluginRuntimeFailures,
} from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import { runCommandPaletteCommand } from "../../support/plugin/editor";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  enableInstalledPluginFromSettings,
  reapplyInstalledPluginFromSettings,
  removePluginActivationFromSettings,
  removePluginApplicationFromSettings,
} from "../../support/plugin/policy";
import {
  installPluginRuntimeApiCapture,
  pluginRuntimeApplicationLoaded,
} from "../../support/plugin/runtime";
import { storageDemoFrameState } from "../../support/plugin/storage-rpc";
import { PLUGIN_COMMAND_STATUS_TIMEOUT_MS } from "../../support/plugin/types";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("installed plugin storage commands run through Host RPC", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-storage-demo",
      pluginId: "io.refmd.storage-demo",
    });
    await createDocument(page, "Storage Demo Plugin Runtime");
    await openDocument(page, "Storage Demo Plugin Runtime");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not loaded",
    });
    await expect
      .poll(() => storageDemoFrameState(page), {
        timeout: 90_000,
        message: "storage demo plugin sandbox did not register storage commands",
      })
      .toEqual(expect.objectContaining({ status: "Storage commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Storage Demo Status"]');
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Write Values");
    await expect(status)
      .toHaveText("STORAGE_WRITE_OK", { timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `storage write command did not update Host status:\nstate=${JSON.stringify(
            await storageDemoFrameState(page),
          )}\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`,
        );
      });
    await expect
      .poll(() => storageDemoFrameState(page), {
        timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
        message: "storage write command did not complete in the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: "Storage write completed" }));

    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("STORAGE_READ_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("UL CACHE WS DOC WREC DREC", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    await page.reload({ waitUntil: "domcontentloaded" });
    await openDocument(page, "Storage Demo Plugin Runtime");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not reloaded",
    });
    await expect
      .poll(() => storageDemoFrameState(page), {
        timeout: 90_000,
        message: "storage demo plugin sandbox did not re-register storage commands",
      })
      .toEqual(expect.objectContaining({ status: "Storage commands registered" }));
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("STORAGE_READ_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("UL CACHE WS DOC WREC DREC", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin storage destructive cleanup removes persisted application data", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-storage-demo",
      pluginId: "io.refmd.storage-demo",
    });
    await createDocument(page, "Storage Demo Destructive Cleanup");
    await openDocument(page, "Storage Demo Destructive Cleanup");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not loaded before cleanup",
    });
    const status = page.locator('.status-bar-item[aria-label="Storage Demo Status"]');
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Write Values");
    await expect(status)
      .toHaveText("STORAGE_WRITE_OK", { timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `storage destructive cleanup write command did not update Host status:\nstate=${JSON.stringify(
            await storageDemoFrameState(page),
          )}\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`,
        );
      });
    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("STORAGE_READ_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    await removePluginApplicationFromSettings(page, "io.refmd.storage-demo");
    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.storage-demo"), {
        timeout: 90_000,
        message: "storage demo runtime remained loaded after application deletion",
      })
      .toBe(false);

    await installPluginFromSettings(page, {
      fixtureName: "refmd-storage-demo",
      pluginId: "io.refmd.storage-demo",
      manifestVersion: "0.1.1",
    });
    await openDocument(page, "Storage Demo Destructive Cleanup");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not reloaded after cleanup",
    });
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("STORAGE_READ_OK: false", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect
      .poll(() => storageDemoFrameState(page), {
        timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
        message: "storage cleanup read result did not reach the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("STORAGE_READ_OK: false") }));

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin storage activation deletion cleanup removes local data only", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const runtimeApiCapture = installPluginRuntimeApiCapture(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-storage-demo",
      pluginId: "io.refmd.storage-demo",
    });
    await createDocument(page, "Storage Demo Activation Cleanup");
    await openDocument(page, "Storage Demo Activation Cleanup");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not loaded before activation cleanup",
    });
    const status = page.locator('.status-bar-item[aria-label="Storage Demo Status"]');
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Write Values");
    await expect(status).toHaveText("STORAGE_WRITE_OK", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("LOCAL_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("SERVER_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    await removePluginActivationFromSettings(page, "io.refmd.storage-demo");
    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.storage-demo"), {
        timeout: 90_000,
        message: "storage demo runtime remained loaded after activation deletion",
      })
      .toBe(false);
    await expect
      .poll(() => storageDemoFrameState(page), {
        timeout: 30_000,
        message: "storage demo sandbox frame remained after activation deletion",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));

    await reapplyInstalledPluginFromSettings(page, "io.refmd.storage-demo");
    await enableInstalledPluginFromSettings(page, "io.refmd.storage-demo");
    await openDocument(page, "Storage Demo Activation Cleanup");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not reloaded after activation cleanup",
      extraDiagnostic: runtimeApiCapture.summary,
    });
    await expect(status).toHaveText("Storage Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(status).toContainText("STORAGE_READ_OK: false", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("LOCAL_OK: false", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("LOCAL_RECORD_OK: false", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });
    await expect(status).toContainText("SERVER_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
