import {
  expect,
  type Locator,
  type Page,
} from "@playwright/test";
import { selectSettingsTab } from "../settings";
import { E2E_DELAYS } from "../timeouts";
import { waitForWorkspaceReady } from "../workspace";
import { allowPluginConsentIfPresent } from "./consent";
import { safePageFrames } from "./diagnostics";
import { ensureInstalledPluginApplicationState } from "./policy";
import { pluginRuntimeDiagnostic } from "./diagnostics";
import {
  expectPluginRowVisible,
  openSettingsDialog,
  pluginRowInSection,
  returnToWorkspaceAfterPluginSettings,
} from "./settings";

export async function savePluginCredentialFromSettings(page: Page, pluginId: string): Promise<void> {
  await returnToWorkspaceAfterPluginSettings(page);
  await openSettingsDialog(page);
  await selectSettingsTab(page, "Community Plugins");

  let dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  let installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  let deviceSection = dialog
    .getByRole("heading", { name: "Device access" })
    .locator("xpath=ancestor::section[1]");
  let installedRow = pluginRowInSection(installedSection, pluginId);
  await expectPluginRowVisible(page, dialog, installedSection, pluginId, "Installed");
  await expectPluginRowVisible(page, dialog, deviceSection, pluginId, "Device access");
  await allowPluginConsentIfPresent(page, 1_000, 30_000);
  await ensureInstalledPluginApplicationState(page, dialog, installedSection, pluginId, "Disabled");
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
  await openSettingsDialog(page);
  await selectSettingsTab(page, "Community Plugins");
  dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  deviceSection = dialog
    .getByRole("heading", { name: "Device access" })
    .locator("xpath=ancestor::section[1]");
  installedRow = pluginRowInSection(installedSection, pluginId);
  await expectPluginRowVisible(page, dialog, installedSection, pluginId, "Installed");
  await expectPluginRowVisible(page, dialog, deviceSection, pluginId, "Device access");
  await expect(installedRow.getByText("Plugin credentials", { exact: true })).toBeVisible({
    timeout: 10_000,
  });
  await installedRow
    .getByRole("combobox", { name: "Endpoint" })
    .selectOption("credential-demo-api", { timeout: 5_000 });
  await installedRow
    .getByRole("combobox", { name: "Method" })
    .selectOption("POST", { timeout: 5_000 });
  await installedRow
    .getByRole("textbox", { name: "Credential ID" })
    .fill("api-key", { timeout: 5_000 });
  await expect(installedRow.getByRole("textbox", { name: "Credential ID" })).toHaveValue(
    "api-key",
    { timeout: 5_000 },
  );
  await installedRow
    .getByRole("textbox", { name: "Header" })
    .fill("authorization", { timeout: 5_000 });
  await expect(installedRow.getByRole("textbox", { name: "Header" })).toHaveValue(
    "authorization",
    { timeout: 5_000 },
  );
  await installedRow
    .getByRole("textbox", { name: "Secret value" })
    .fill("Bearer refmd-e2e-secret", { timeout: 5_000 });
  await expect(installedRow.getByRole("textbox", { name: "Secret value" })).toHaveValue(
    "Bearer refmd-e2e-secret",
    { timeout: 5_000 },
  );

  const saveButton = installedRow.getByRole("button", { name: "Save credential" });
  await expect(saveButton).toBeEnabled({ timeout: 10_000 });
  await saveButton.click({ force: true, timeout: 5_000 });
  await waitForPluginCredentialSaved(page, dialog, pluginId);
  await returnToWorkspaceAfterPluginSettings(page);
}

export async function waitForPluginCredentialSaved(
  page: Page,
  dialog: Locator,
  pluginId: string,
): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (
      await dialog
        .getByText("Plugin credential saved.", { exact: false })
        .isVisible({ timeout: 1_000 })
        .catch(() => false)
    ) {
      return;
    }
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }
  throw new Error(
    `Plugin credential save did not complete for ${pluginId}:\n${await dialog.textContent()}\n${await pluginRuntimeDiagnostic(page)}`,
  );
}

export async function credentialDemoFrameState(page: Page): Promise<{
  status: string | null;
  frameCount: number;
  frameTexts: string[];
}> {
  const frameTexts: string[] = [];
  let status: string | null = null;
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("Handle Demo Plugin")) continue;
    frameTexts.push(state.bodyText.slice(0, 500));
    status = state.status;
  }
  return { status, frameCount: frameTexts.length, frameTexts };
}
