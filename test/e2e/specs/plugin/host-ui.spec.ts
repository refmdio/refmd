import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { allowPluginConsentIfPresent } from "../../support/plugin/consent";
import { watchPluginRuntimeFailures } from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import {
  collectPluginHostUiDiagnostics,
  expectUiDemoFrameRendered,
  expectUiDemoModal,
  openDocumentTileMenu,
} from "../../support/plugin/host-ui";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  installPluginRuntimeApiCapture,
  pluginRuntimeApplicationLoaded,
} from "../../support/plugin/runtime";
import {
  closeSettingsDialogIfOpen,
  getSettingsDialog,
} from "../../support/plugin/settings";
import { PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS } from "../../support/plugin/types";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("plugin Host UI contributions register through an installed plugin and render in Host UI", async ({
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
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Plugin Runtime");
    await openDocument(page, "UI Demo Plugin Runtime");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded",
      })
      .toBe(true)
      .catch(async (error) => {
        throw new Error(
          `UI demo plugin runtime application was not loaded:\nruntimeFailures=${JSON.stringify(
            runtimeFailures(),
          )}\nruntimeApi=${runtimeApiCapture.summary()}\n${await collectPluginHostUiDiagnostics(page)}\n${String(error)}`,
        );
      });
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]'))
      .toHaveText("UI Demo Ready", { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `UI demo status contribution did not render:\nruntimeFailures=${JSON.stringify(
            runtimeFailures(),
          )}\nruntimeApi=${runtimeApiCapture.summary()}\n${await collectPluginHostUiDiagnostics(page)}\n${String(error)}`,
        );
      });
    await expectUiDemoFrameRendered(page, "UI Demo Status Frame", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      runtimeApi: runtimeApiCapture.summary,
      runtimeFailures,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expectUiDemoFrameRendered(page, "UI Demo Comments", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      runtimeApi: runtimeApiCapture.summary,
      runtimeFailures,
    });
    await openDocumentTileMenu(page);
    await page.getByRole("menuitem", { name: "UI Demo Workspace Tile" }).click();
    await expectUiDemoFrameRendered(page, "UI Demo Workspace Tile", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      runtimeApi: runtimeApiCapture.summary,
      runtimeFailures,
    });

    const sidebarButton = page.getByRole("button", { name: "UI Demo Sidebar" });
    await expect(sidebarButton).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    const treeRow = page
      .locator("aside button", { hasText: "UI Demo Plugin Runtime" })
      .first();
    await expect(treeRow).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
    await expect(treeRow.getByText("dt", { exact: true })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await treeRow.click({ button: "right" });
    const treeAction = page.getByRole("menuitem", { name: "UI Demo Tree Action" });
    await expect(treeAction).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
    await treeAction.click();
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "Command invoked: trigger.modal (document)",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );

    await expect(sidebarButton).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await sidebarButton.click();
    await expectUiDemoFrameRendered(page, "UI Demo Sidebar", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      runtimeApi: runtimeApiCapture.summary,
      runtimeFailures,
    });
    await page.getByRole("button", { name: "Document Tree" }).click();

    await openSettings(page);
    await selectSettingsTab(page, "UI Demo Settings");
    const settingsDialog = getSettingsDialog(page);
    await expect(settingsDialog.getByText("UI Demo Controls", { exact: true })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(settingsDialog.getByText("UI Demo Note", { exact: true })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await settingsDialog.getByLabel("UI Demo Note").fill("settings-e2e");
    await settingsDialog.getByLabel("UI Demo Enabled").check();
    await settingsDialog.getByRole("button", { name: "Submit" }).click();
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "Settings saved: note=settings-e2e enabled=true",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await selectSettingsTab(page, "UI Demo Iframe Settings");
    await expect(
      page.frameLocator('iframe[title="UI Demo Iframe Settings"]').locator("body"),
    ).toContainText("RefMD UI Demo Plugin", { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
    await closeSettingsDialogIfOpen(page);

    await page.keyboard.press("Control+P");
    const commandInput = page.locator('input[placeholder="Type a command..."]');
    const commandDialog = page.locator('[role="dialog"]').filter({ has: commandInput });
    await expect(commandInput).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
    await commandInput.fill("UI Demo Modal");
    await commandDialog.getByText("UI Demo Modal", { exact: true }).click();

    await expectUiDemoModal(page);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
