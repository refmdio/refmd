import {
  expect,
  type Locator,
  type Page,
} from "@playwright/test";
import { openSettings } from "../settings";
import { E2E_DELAYS } from "../timeouts";
import { waitForWorkspaceReady } from "../workspace";
import {
  allowPluginConsentIfPresent,
  closePluginConsentIfPresent,
} from "./consent";
import { pluginRuntimeDiagnostic } from "./diagnostics";

export async function clickDialogCloseButton(closeButton: Locator): Promise<void> {
  await closeButton.click({ timeout: 2_000 }).catch(async (clickError) => {
    await closeButton.click({ timeout: 2_000, force: true }).catch(async (forceClickError) => {
      const handle = await closeButton.elementHandle({ timeout: 1_000 }).catch(() => null);
      if (!handle) {
        throw new Error(
          `Dialog close button was not available:\nnormal=${String(clickError)}\nforce=${String(
            forceClickError,
          )}`,
        );
      }
      await handle.evaluate((node) => {
        if (node instanceof HTMLElement) node.click();
      });
    });
  });
}

export async function closeOpenDialogOverlays(page: Page): Promise<void> {
  const overlays = page.locator('[data-slot="dialog-overlay"]');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    if ((await overlays.count().catch(() => 0)) === 0) return;
    const dialog = page.locator('[role="dialog"]').last();
    const closeButton = dialog
      .locator('[data-slot="dialog-close"]')
      .or(dialog.getByRole("button", { name: "Close" }))
      .or(dialog.getByRole("button", { name: "Done" }))
      .last();
    if (await closeButton.isVisible({ timeout: 500 }).catch(() => false)) {
      await closeButton.click({ timeout: 2_000 }).catch(() => {});
    }
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }
  if ((await overlays.count().catch(() => 0)) > 0) {
    await page.reload({ waitUntil: "domcontentloaded" }).catch(() => {});
    await waitForWorkspaceReady(page);
  }
  await expect(overlays).toHaveCount(0, { timeout: 10_000 });
}

export function getSettingsDialog(page: Page) {
  return page.locator('[role="dialog"]').filter({
    has: page.getByRole("heading", { name: "Settings" }),
  });
}

export function pluginRowInSection(section: Locator, pluginId: string): Locator {
  return section
    .getByText(pluginTextPattern(pluginId))
    .first()
    .locator(
      "xpath=ancestor::div[contains(concat(' ', normalize-space(@class), ' '), ' border-b ')][1]",
    );
}

export function pluginTextPattern(pluginId: string): RegExp {
  return new RegExp(`^${escapeRegExp(pluginId)}(?:\\s|$)`);
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function refreshCommunityPluginsIfAvailable(dialog: Locator): Promise<void> {
  const refreshButton = dialog.locator('button[title="Refresh"]').first();
  if (
    (await refreshButton.isVisible({ timeout: 1_000 }).catch(() => false)) &&
    (await refreshButton.isEnabled().catch(() => false))
  ) {
    const clicked = await refreshButton
      .click({ timeout: 10_000 })
      .then(() => true)
      .catch(() => false);
    if (clicked) await dialog.page().waitForTimeout(E2E_DELAYS.overlaySettle);
  }
}

export async function settlePluginConsentBeforeSettings(page: Page): Promise<void> {
  await allowPluginConsentIfPresent(page, 1_000, 30_000).catch(async () => {
    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(page);
  });
}

export async function expectPluginRowVisible(
  page: Page,
  dialog: Locator,
  section: Locator,
  pluginId: string,
  sectionName: string,
  timeout = 60_000,
): Promise<Locator> {
  const row = pluginRowInSection(section, pluginId);
  await expect(row)
    .toBeVisible({ timeout: Math.min(timeout, 10_000) })
    .catch(async () => {
      await allowPluginConsentIfPresent(page, 5_000).catch(() =>
        closePluginConsentIfPresent(page, 5_000),
      );
      await refreshCommunityPluginsIfAvailable(dialog);
      await allowPluginConsentIfPresent(page, 5_000).catch(() =>
        closePluginConsentIfPresent(page, 5_000),
      );
      await expect(row)
        .toBeVisible({ timeout })
        .catch(async (error) => {
          throw new Error(
            `Community Plugins ${sectionName} section did not show ${pluginId}:\nsection=${await section.textContent()}\ndialog=${await dialog.textContent()}\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`,
          );
        });
    });
  return row;
}

export async function clickPluginRowButton(
  button: Locator,
  options: {
    success?: Locator;
  } = {},
): Promise<void> {
  const isDone = async () =>
    (await options.success?.isVisible({ timeout: 500 }).catch(() => false)) === true;

  await expect(button).toBeEnabled({ timeout: 30_000 });
  await button.click({ timeout: 10_000 }).catch(async (clickError) => {
    if (await isDone()) return;
    if (!(await button.isVisible({ timeout: 500 }).catch(() => false))) return;
    await expect(button).toBeEnabled({ timeout: 10_000 });
    await button.click({ timeout: 5_000, force: true }).catch(async (forceClickError) => {
      if (await isDone()) return;
      const handle = await button.elementHandle({ timeout: 1_000 }).catch(() => null);
      if (!handle) {
        throw new Error(
          `Plugin row button click failed:\nnormal=${String(clickError)}\nforce=${String(
            forceClickError,
          )}\ndom=element_not_available`,
        );
      }
      await handle
        .evaluate((node) => {
          if (node instanceof HTMLButtonElement && node.disabled) {
            throw new Error("plugin row button is disabled");
          }
          if (node instanceof HTMLElement) node.click();
        })
        .catch((domClickError) => {
          throw new Error(
            `Plugin row button click failed:\nnormal=${String(clickError)}\nforce=${String(
              forceClickError,
            )}\ndom=${String(domClickError)}`,
          );
        });
    });
  });
  if (await isDone()) return;
}

export async function pluginRowStateVisible(
  section: Locator,
  pluginId: string,
  state: "Enabled" | "Disabled" | "Allowed" | "Denied",
): Promise<boolean> {
  return pluginRowInSection(section, pluginId)
    .getByText(state, { exact: true })
    .isVisible({ timeout: 1_000 })
    .catch(() => false);
}

export async function waitForPluginRowState(
  page: Page,
  dialog: Locator,
  section: Locator,
  pluginId: string,
  state: "Enabled" | "Disabled" | "Allowed" | "Denied",
  options: { timeout: number; success?: Locator } = { timeout: 30_000 },
): Promise<boolean> {
  const deadline = Date.now() + options.timeout;
  let nextRefreshAt = Date.now();
  while (Date.now() < deadline) {
    if (await pluginRowStateVisible(section, pluginId, state)) {
      return true;
    }
    if (Date.now() >= nextRefreshAt) {
      await refreshCommunityPluginsIfAvailable(dialog);
      nextRefreshAt = Date.now() + 2_000;
      if (await pluginRowStateVisible(section, pluginId, state)) {
        return true;
      }
    }
    await allowPluginConsentIfPresent(page, 250).catch(() => undefined);
    await page.waitForTimeout(E2E_DELAYS.poll);
  }
  return false;
}

export async function pluginManagementBusyAction(page: Page): Promise<string> {
  return page
    .locator("[data-refmd-plugin-management-busy-action]")
    .first()
    .getAttribute("data-refmd-plugin-management-busy-action", { timeout: 1_000 })
    .then((value) => value ?? "")
    .catch(() => "");
}

export async function pluginRowButtonDiagnostic(row: Locator): Promise<
  Array<{
    title: string | null;
    ariaLabel: string | null;
    text: string;
    disabled: boolean;
    visible: boolean;
  }>
> {
  return row
    .locator("button")
    .evaluateAll((buttons) =>
      buttons.map((button) => ({
        title: button.getAttribute("title"),
        ariaLabel: button.getAttribute("aria-label"),
        text: button.textContent?.trim() ?? "",
        disabled:
          button instanceof HTMLButtonElement
            ? button.disabled
            : button.getAttribute("aria-disabled") === "true",
        visible: Boolean(button.offsetParent || button.getClientRects().length),
      })),
    )
    .catch(() => []);
}

export async function closeSettingsDialogIfOpen(page: Page, timeout = 10_000): Promise<void> {
  const dialog = getSettingsDialog(page);
  if (!(await dialog.isVisible({ timeout: 1_000 }).catch(() => false))) {
    return;
  }

  const closeButton = dialog.locator('[data-slot="dialog-close"]').last();
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (!(await dialog.isVisible({ timeout: 500 }).catch(() => false))) {
      return;
    }
    if (await closeButton.isVisible({ timeout: 500 }).catch(() => false)) {
      await clickDialogCloseButton(closeButton).catch(() => {});
    } else {
      await page.keyboard.press("Escape");
    }
    if (!(await dialog.isVisible({ timeout: 1_000 }).catch(() => false))) {
      return;
    }
  }

  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
  await expect(dialog).toHaveCount(0, { timeout: 5_000 });
}

export async function returnToWorkspaceAfterPluginSettings(page: Page): Promise<void> {
  await closeSettingsDialogIfOpen(page);
  const settingsDialog = getSettingsDialog(page);
  const consentDialog = page.getByRole("dialog", { name: "Plugin Consent" });
  const hasBlockingDialog =
    (await settingsDialog.isVisible({ timeout: 1_000 }).catch(() => false)) ||
    (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false));
  if (hasBlockingDialog) {
    await page.reload({ waitUntil: "domcontentloaded" });
  }
  await waitForWorkspaceReady(page);
}

export async function openSettingsDialog(page: Page): Promise<Locator> {
  const dialog = getSettingsDialog(page);
  const consentDialog = page.getByRole("dialog", { name: "Plugin Consent" });
  let lastError: unknown;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await waitForWorkspaceReady(page);
    if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
      await settlePluginConsentBeforeSettings(page);
      if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await page.reload({ waitUntil: "domcontentloaded" });
      }
      continue;
    }
    if (await dialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
      return dialog;
    }

    try {
      await clickSettingsControl(page);
    } catch (error) {
      lastError = error;
    }

    if (await dialog.isVisible({ timeout: 5_000 }).catch(() => false)) {
      if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await settlePluginConsentBeforeSettings(page);
        continue;
      }
      return dialog;
    }
    await openSettings(page).catch((error) => {
      lastError = error;
    });
    if (!(await dialog.isVisible({ timeout: 2_000 }).catch(() => false))) {
      await page
        .evaluate(() => {
          const buttons = Array.from(document.querySelectorAll<HTMLElement>("button"));
          const settingsButton = buttons.find(
            (node) =>
              node.getAttribute("aria-label") === "Settings" ||
              node.getAttribute("title") === "Settings" ||
              node.textContent?.trim() === "Settings",
          );
          settingsButton?.click();
          return Boolean(settingsButton);
        })
        .catch((error) => {
          lastError = error;
        });
    }
    if (await dialog.isVisible({ timeout: 5_000 }).catch(() => false)) {
      if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await settlePluginConsentBeforeSettings(page);
        continue;
      }
      return dialog;
    }
    if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
      await settlePluginConsentBeforeSettings(page);
    }
  }

  if (/\/dashboard(?:$|\?)/.test(new URL(page.url()).pathname)) {
    await page.reload({ waitUntil: "domcontentloaded" }).catch((error) => {
      lastError = error;
    });
  } else {
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" }).catch((error) => {
      lastError = error;
    });
  }
  await waitForWorkspaceReady(page);
  await clickSettingsControl(page).catch((error) => {
    lastError = error;
  });
  if (await dialog.isVisible({ timeout: 10_000 }).catch(() => false)) {
    if (await consentDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
      await settlePluginConsentBeforeSettings(page);
      if (!(await dialog.isVisible({ timeout: 2_000 }).catch(() => false))) {
        await clickSettingsControl(page).catch((error) => {
          lastError = error;
        });
      }
    }
    return dialog;
  }

  throw new Error(
    `Settings dialog did not open:\n${await pluginRuntimeDiagnostic(
      page,
    )}\nsettingsControls=${JSON.stringify(await settingsControlDiagnostic(page))}\n${String(
      lastError ?? "",
    )}`,
  );
}

export async function clickSettingsControl(page: Page): Promise<void> {
  const settingsButton = page
    .getByRole("button", { name: "Settings" })
    .or(page.locator('button[aria-label="Settings"], button[title="Settings"]'))
    .first();
  if (await settingsButton.isVisible({ timeout: 10_000 }).catch(() => false)) {
    await settingsButton.click({ timeout: 5_000 }).catch(async () => {
      await settingsButton.click({ timeout: 5_000, force: true });
    });
    return;
  }

  const clicked = await page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll<HTMLElement>("button"));
    const settingsButton = buttons.find(
      (node) =>
        node.getAttribute("aria-label") === "Settings" ||
        node.getAttribute("title") === "Settings" ||
        node.textContent?.trim() === "Settings",
    );
    settingsButton?.click();
    return Boolean(settingsButton);
  });
  if (!clicked) {
    throw new Error("Settings control was not found");
  }
}

export async function settingsControlDiagnostic(page: Page) {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>("aside button, button"))
      .slice(0, 40)
      .map((node) => ({
        ariaLabel: node.getAttribute("aria-label"),
        title: node.getAttribute("title"),
        text: node.textContent?.trim().slice(0, 80) ?? "",
        visible: Boolean(node.offsetParent || node.getClientRects().length),
      })),
  );
}
