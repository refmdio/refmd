import {
  expect,
  type Locator,
  type Page,
} from "@playwright/test";
import {
  openSettings,
  selectSettingsTab,
} from "../settings";
import { E2E_DELAYS } from "../timeouts";
import { waitForWorkspaceReady } from "../workspace";
import {
  allowPluginConsentIfPresent,
  closePluginConsentIfPresent,
  pluginStatePinDiagnostic,
} from "./consent";
import { pluginRuntimeDiagnostic } from "./diagnostics";
import {
  clickPluginRowButton,
  closeSettingsDialogIfOpen,
  expectPluginRowVisible,
  openSettingsDialog,
  pluginManagementBusyAction,
  pluginRowButtonDiagnostic,
  pluginRowInSection,
  pluginRowStateVisible,
  refreshCommunityPluginsIfAvailable,
  returnToWorkspaceAfterPluginSettings,
  waitForPluginRowState,
} from "./settings";
import { PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS } from "./types";

export async function tryAllowInstalledPluginPolicy(
  page: Page,
  dialog: Locator,
  installedSection: Locator,
  pluginId: string,
  timeout = 60_000,
): Promise<boolean> {
  let deadline = Date.now() + timeout;
  let clicked = false;
  let lastClickError: unknown;

  while (Date.now() < deadline) {
    if (await pluginRowStateVisible(installedSection, pluginId, "Allowed")) {
      return true;
    }

    const installedRow = pluginRowInSection(installedSection, pluginId);
    const allowButton = installedRow.locator('button[title="Allow plugin"]');
    if (await allowButton.isVisible({ timeout: 1_000 }).catch(() => false)) {
      deadline = Math.max(deadline, Date.now() + 60_000);
      await allowPluginConsentIfPresent(page, 5_000);
      const success = dialog.getByText("Plugin allowed.", { exact: false });
      await clickPluginRowButton(allowButton, { success })
        .then(() => {
          clicked = true;
        })
        .catch(async (error) => {
          lastClickError = error;
          if (await pluginRowStateVisible(installedSection, pluginId, "Allowed")) {
            return;
          }
          throw error;
        });
      await allowPluginConsentIfPresent(page, 5_000, 120_000).catch(() => undefined);
      if (
        await waitForPluginRowState(page, dialog, installedSection, pluginId, "Allowed", {
          timeout: Math.min(15_000, Math.max(1_000, deadline - Date.now())),
          success,
        })
      ) {
        return true;
      }
    }

    await refreshCommunityPluginsIfAvailable(dialog);
    if (await pluginRowStateVisible(installedSection, pluginId, "Allowed")) {
      return true;
    }
    await page.waitForTimeout(E2E_DELAYS.poll);
  }

  if (clicked) {
    throw new Error(
      `Plugin allow action did not persist Allowed state for ${pluginId}:\nsection=${await installedSection.textContent()}\ndialog=${await dialog.textContent()}\nstatePins=${await pluginStatePinDiagnostic(
        page,
      )}\n${await pluginRuntimeDiagnostic(page)}\nlastClickError=${String(lastClickError ?? "")}`,
    );
  }
  return false;
}

export async function ensureInstalledPluginPolicyAllowed(
  page: Page,
  dialog: Locator,
  installedSection: Locator,
  pluginId: string,
  timeout = 90_000,
): Promise<void> {
  if (await tryAllowInstalledPluginPolicy(page, dialog, installedSection, pluginId, timeout)) {
    return;
  }
  throw new Error(
    `Community Plugins did not expose durable Allowed state for ${pluginId}:\nsection=${await installedSection.textContent()}\ndialog=${await dialog.textContent()}\nstatePins=${await pluginStatePinDiagnostic(
      page,
    )}\n${await pluginRuntimeDiagnostic(page)}`,
  );
}

export async function ensureInstalledPluginApplicationState(
  page: Page,
  dialog: Locator,
  installedSection: Locator,
  pluginId: string,
  state: "Enabled" | "Disabled",
  timeout = PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
): Promise<void> {
  const title = state === "Enabled" ? "Enable" : "Disable";
  const successText = state === "Enabled" ? "Plugin enabled." : "Plugin disabled.";
  const deadline = Date.now() + timeout;
  let lastError: unknown;
  let lastButtonDiagnostic: unknown = null;

  while (Date.now() < deadline) {
    if (await pluginRowStateVisible(installedSection, pluginId, state)) return;

    const row = pluginRowInSection(installedSection, pluginId);
    const button = row.locator(`button[title="${title}"]`);
    lastButtonDiagnostic = await pluginRowButtonDiagnostic(row);
    if (await button.isVisible({ timeout: 750 }).catch(() => false)) {
      if (await button.isEnabled().catch(() => false)) {
        const success = dialog.getByText(successText, { exact: false });
        await allowPluginConsentIfPresent(page, 1_000, 30_000).catch(() => undefined);
        await clickPluginRowButton(button, { success }).catch((error) => {
          lastError = error;
        });
        if (
          await waitForPluginRowState(page, dialog, installedSection, pluginId, state, {
            timeout: Math.min(15_000, Math.max(1_000, deadline - Date.now())),
            success,
          })
        ) {
          return;
        }
      }
    }

    await refreshCommunityPluginsIfAvailable(dialog);
    if (await pluginRowStateVisible(installedSection, pluginId, state)) return;
    await page.waitForTimeout(E2E_DELAYS.poll);
  }

  throw new Error(
    `Community Plugins did not reach ${state} state for ${pluginId}:\nsection=${await installedSection.textContent()}\ndialog=${await dialog.textContent()}\n${await pluginRuntimeDiagnostic(
      page,
    )}\nbusyAction=${await pluginManagementBusyAction(page)}\nbuttons=${JSON.stringify(
      lastButtonDiagnostic,
    )}\nlastError=${String(lastError ?? "")}`,
  );
}

export async function enableInstalledPluginFromSettings(page: Page, pluginId: string): Promise<void> {
  await returnToWorkspaceAfterPluginSettings(page);
  await openSettingsDialog(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  await expectPluginRowVisible(
    page,
    dialog,
    installedSection,
    pluginId,
    "Installed",
  );
  await ensureInstalledPluginApplicationState(page, dialog, installedSection, pluginId, "Enabled");
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
}

export async function reapplyInstalledPluginFromSettings(page: Page, pluginId: string): Promise<void> {
  await closePluginConsentIfPresent(page, 5_000);
  await openSettingsDialog(page);
  await closePluginConsentIfPresent(page, 5_000);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const availableSection = dialog
    .getByRole("heading", { name: "Available plugins" })
    .locator("xpath=ancestor::section[1]");
  const packageRow = pluginRowInSection(availableSection, pluginId);
  await expect(packageRow)
    .toBeVisible({ timeout: 60_000 })
    .catch(async (error) => {
      throw new Error(
        `Available plugins did not list ${pluginId} before reapply:\n${await availableSection.textContent()}\n${String(error)}`,
      );
    });
  const reapplyButton = packageRow.getByRole("button", { name: "Reapply" });
  await expect(reapplyButton)
    .toBeEnabled({ timeout: 30_000 })
    .catch(async (error) => {
      throw new Error(
        `Available plugin row did not expose an enabled Reapply action for ${pluginId}:\n${await packageRow.textContent()}\n${String(error)}`,
      );
    });
  await reapplyButton.click();
  await expect
    .poll(() => pluginStatePinDiagnostic(page), {
      timeout: 30_000,
      message: `Plugin reapply did not persist a state pin for ${pluginId}`,
    })
    .not.toBe("[]")
    .catch(async (error) => {
      throw new Error(
        `Plugin reapply did not persist a state pin for ${pluginId}:\n${await dialog.textContent()}\n${String(error)}`,
      );
    });

  await expect
    .poll(() => dialog.textContent(), {
      timeout: 30_000,
      message: `Plugin reapply did not expose device access for ${pluginId}`,
    })
    .toContain(pluginId)
    .catch(async (error) => {
      throw new Error(
        `Plugin reapply did not expose device access for ${pluginId}:\n${await dialog.textContent()}\n${String(error)}`,
      );
    });

  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  await ensureInstalledPluginApplicationState(page, dialog, installedSection, pluginId, "Enabled");

  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
}

export async function allowInstalledPluginFromSettings(page: Page, pluginId: string): Promise<void> {
  await returnToWorkspaceAfterPluginSettings(page);
  await openSettingsDialog(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  await expectPluginRowVisible(
    page,
    dialog,
    installedSection,
    pluginId,
    "Installed",
  );
  await refreshCommunityPluginsIfAvailable(dialog);
  await expectPluginRowVisible(
    page,
    dialog,
    installedSection,
    pluginId,
    "Installed",
    30_000,
  );
  const deviceSection = dialog
    .getByRole("heading", { name: "Device access" })
    .locator("xpath=ancestor::section[1]");
  const tryAllowWorkspacePolicy = async (timeout: number) => {
    const allowed = await tryAllowInstalledPluginPolicy(
      page,
      dialog,
      installedSection,
      pluginId,
      timeout,
    );
    return allowed;
  };
  let trustedCurrentDevice = await currentDevicePluginAccessVisible(
    page,
    installedSection,
    deviceSection,
    pluginId,
  );
  if (await tryAllowWorkspacePolicy(2_000)) {
    trustedCurrentDevice = await currentDevicePluginAccessVisible(
      page,
      installedSection,
      deviceSection,
      pluginId,
    );
  }

  const availableSection = dialog
    .getByRole("heading", { name: "Available plugins" })
    .locator("xpath=ancestor::section[1]");
  const packageRow = pluginRowInSection(availableSection, pluginId);
  const tryReapply = async (timeout: number) => {
    if (
      await currentDevicePluginAccessVisible(page, installedSection, deviceSection, pluginId)
    ) {
      return true;
    }
    const reapplyButton = packageRow.getByRole("button", { name: "Reapply" });
    if (
      !(await reapplyButton.isVisible({ timeout }).catch(() => false)) ||
      !(await reapplyButton.isEnabled().catch(() => false))
    ) {
      return false;
    }
    await expect(reapplyButton).toBeEnabled({ timeout: 10_000 });
    await allowPluginConsentIfPresent(page, 5_000);
    await reapplyButton.click();
    await expect(dialog.getByText("Plugin applied to workspace.", { exact: false }))
      .toBeVisible({
        timeout: 60_000,
      })
      .catch(async (error) => {
        throw new Error(
          `Plugin reapply did not complete for ${pluginId}:\n${await dialog.textContent()}\n${String(error)}`,
        );
      });
    await tryAllowWorkspacePolicy(5_000);
    await expect
      .poll(() => currentDevicePluginAccessVisible(page, installedSection, deviceSection, pluginId), {
        timeout: 30_000,
        message: `Plugin reapply did not establish current-device access for ${pluginId}`,
      })
      .toBe(true)
      .catch(async (error) => {
        throw new Error(
          `Plugin reapply did not establish current-device access for ${pluginId}:\n${await dialog.textContent()}\nstatePins=${await pluginStatePinDiagnostic(
            page,
          )}\n${String(error)}`,
        );
      });
    return true;
  };
  if (!trustedCurrentDevice) trustedCurrentDevice = await tryReapply(2_000);
  if (!trustedCurrentDevice) {
    await refreshCommunityPluginsIfAvailable(dialog);
    await expectPluginRowVisible(page, dialog, installedSection, pluginId, "Installed", 30_000);
    trustedCurrentDevice = await currentDevicePluginAccessVisible(
      page,
      installedSection,
      deviceSection,
      pluginId,
    );
  }
  if (!trustedCurrentDevice) {
    trustedCurrentDevice = await tryReapply(5_000);
  }
  expect(
    trustedCurrentDevice,
    `Community Plugins did not expose current-device access for ${pluginId}:\n${await dialog.textContent()}\nstatePins=${await pluginStatePinDiagnostic(
      page,
    )}`,
  ).toBe(true);
  await ensureInstalledPluginApplicationState(page, dialog, installedSection, pluginId, "Enabled");
  await returnToWorkspaceAfterPluginSettings(page);
}

export async function currentDevicePluginAccessVisible(
  page: Page,
  installedSection: Locator,
  deviceSection: Locator,
  pluginId: string,
): Promise<boolean> {
  const installedRow = pluginRowInSection(installedSection, pluginId);
  const installedAllowed = await installedRow
    .getByText("Allowed", { exact: true })
    .isVisible({ timeout: 1_000 })
    .catch(() => false);
  if (!installedAllowed) return false;

  const deviceRow = pluginRowInSection(deviceSection, pluginId);
  const deviceText = (await deviceRow.textContent({ timeout: 1_000 }).catch(() => "")) ?? "";
  const deviceEnabled =
    /\b(Device\s+)?Enabled\b/.test(deviceText) ||
    (await deviceRow
      .getByText("Enabled", { exact: true })
      .isVisible({ timeout: 1_000 })
      .catch(() => false));
  if (!deviceEnabled) return false;

  return pluginStatePinsAvailable(await pluginStatePinDiagnostic(page));
}

export function pluginStatePinsAvailable(value: string): boolean {
  if (
    value === "store_missing" ||
    value.startsWith("open_error:") ||
    value.startsWith("get_all_error:")
  ) {
    return false;
  }
  try {
    const pins = JSON.parse(value) as unknown;
    return Array.isArray(pins) && pins.length > 0;
  } catch {
    return false;
  }
}

export async function disableInstalledPluginFromSettings(page: Page, pluginId: string): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  const installedRow = pluginRowInSection(installedSection, pluginId);
  await expect(installedRow).toBeVisible({ timeout: 30_000 });
  await ensureInstalledPluginApplicationState(page, dialog, installedSection, pluginId, "Disabled");
  await closeSettingsDialogIfOpen(page);
}

export async function removePluginActivationFromSettings(page: Page, pluginId: string): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const deviceSection = dialog
    .getByRole("heading", { name: "Device access" })
    .locator("xpath=ancestor::section[1]");
  const activationRows = pluginRowInSection(deviceSection, pluginId);
  await expect(activationRows).toHaveCount(1, { timeout: 30_000 });
  await activationRows.first().locator('button[title="Remove from this device"]').click();
  await expect(dialog.getByText("Plugin removed from this device.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });
  await expect(activationRows).toHaveCount(0, { timeout: 30_000 });
  await closeSettingsDialogIfOpen(page);
  await expect(page.getByRole("dialog", { name: "Plugin Consent" })).toHaveCount(0, {
    timeout: 30_000,
  });
}

export async function removePluginApplicationFromSettings(page: Page, pluginId: string): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  const installedRows = pluginRowInSection(installedSection, pluginId);
  await expect(installedRows).toHaveCount(1, { timeout: 30_000 });
  await installedRows.first().locator('button[title="Remove"]').click();
  await expect(dialog.getByText("Plugin removed from workspace.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });
  await expect(installedRows).toHaveCount(0, { timeout: 30_000 });

  const deviceSection = dialog
    .getByRole("heading", { name: "Device access" })
    .locator("xpath=ancestor::section[1]");
  await expect(pluginRowInSection(deviceSection, pluginId)).toHaveCount(0, { timeout: 30_000 });
  await closeSettingsDialogIfOpen(page);
}

export async function revokePluginConsentFromSettings(page: Page, pluginId: string): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  const installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");
  const installedRows = pluginRowInSection(installedSection, pluginId);
  await expect(installedRows).toHaveCount(1, { timeout: 30_000 });
  await installedRows.first().locator('button[title="Revoke consent"]').click();
  await expect(dialog.getByText("Plugin consent revoked.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });
  await closeSettingsDialogIfOpen(page);
}
