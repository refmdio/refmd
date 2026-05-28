import {
  expect,
  type Locator,
  type Page,
} from "@playwright/test";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  openSettings,
  selectSettingsTab,
} from "../settings";
import { E2E_DELAYS } from "../timeouts";
import { pluginStatePinDiagnostic } from "./consent";
import {
  ensureInstalledPluginApplicationState,
  ensureInstalledPluginPolicyAllowed,
} from "./policy";
import {
  closeSettingsDialogIfOpen,
  expectPluginRowVisible,
  pluginRowInSection,
  returnToWorkspaceAfterPluginSettings,
} from "./settings";

export async function installDemoPluginFromSettings(page: Page): Promise<void> {
  await installPluginFromSettings(page, {
    fixtureName: "refmd-renderer-demo",
    pluginId: "io.refmd.renderer-demo",
    summaryText: "Renderer slots",
  });
}

export async function installPluginFromSettings(
  page: Page,
  plugin: {
    fixtureName: string;
    pluginId: string;
    summaryText?: string;
    enable?: boolean;
    ownerScopeKind?: "user" | "workspace";
    manifestVersion?: string;
  },
): Promise<void> {
  const zipPath = buildPluginArchive(plugin.fixtureName, { version: plugin.manifestVersion });

  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  let dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  await expect(dialog.getByRole("heading", { name: "Community Plugins" })).toBeVisible({
    timeout: 10_000,
  });

  await dialog.getByRole("button", { name: "Upload" }).click();
  await dialog.locator('input[type="file"]').setInputFiles(zipPath);
  await reviewUploadedPlugin(page, dialog, plugin.pluginId);

  await expect(dialog.getByText(plugin.pluginId, { exact: true }).first()).toBeVisible({
    timeout: 60_000,
  });
  if (plugin.summaryText) {
    await expect(dialog.getByText(plugin.summaryText, { exact: true })).toBeVisible({
      timeout: 10_000,
    });
  }
  if (plugin.ownerScopeKind) {
    const scopeButtonName = plugin.ownerScopeKind === "workspace" ? "Workspace" : "Personal";
    const scopeButton = dialog.getByRole("button", { name: scopeButtonName });
    if (await scopeButton.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await scopeButton.click();
    }
  }

  const approveButton = dialog.getByRole("button", { name: "Approve Plugin" });
  await expect(approveButton).toBeEnabled({ timeout: 60_000 });
  await approveButton.click();

  await expect(dialog.getByText("Plugin approved.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });

  let availableSection = dialog
    .getByRole("heading", { name: "Available plugins" })
    .locator("xpath=ancestor::section[1]");
  let installedSection = dialog
    .getByRole("heading", { name: "Installed" })
    .locator("xpath=ancestor::section[1]");

  const availableRow = pluginRowInSection(availableSection, plugin.pluginId);
  await expect(availableRow).toBeVisible({ timeout: 60_000 });
  const applyButton = availableRow.getByRole("button", { name: "Apply", exact: true });
  const reapplyButton = availableRow.getByRole("button", { name: "Reapply", exact: true });
  const pinsBeforeApply = await pluginStatePinDiagnostic(page);
  let usedReapply = false;
  if (await applyButton.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await applyButton.click({ timeout: 10_000 });
  } else {
    await expect(reapplyButton).toBeVisible({ timeout: 10_000 });
    await reapplyButton.click({ timeout: 10_000 });
    usedReapply = true;
  }
  await expect(dialog.getByText("Plugin applied to workspace.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });
  const pinsAfterApply = await pluginStatePinDiagnostic(page);
  const applyPersistedStatePin = pinsAfterApply !== pinsBeforeApply && pinsAfterApply !== "[]";
  await page.waitForTimeout(E2E_DELAYS.shortPoll);

  if (usedReapply || plugin.manifestVersion) {
    await closeSettingsDialogIfOpen(page);
    await openSettings(page);
    await selectSettingsTab(page, "Community Plugins");
    dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
    await expect(dialog.getByRole("heading", { name: "Community Plugins" })).toBeVisible({
      timeout: 10_000,
    });
    availableSection = dialog
      .getByRole("heading", { name: "Available plugins" })
      .locator("xpath=ancestor::section[1]");
    installedSection = dialog
      .getByRole("heading", { name: "Installed" })
      .locator("xpath=ancestor::section[1]");
    await expect(pluginRowInSection(availableSection, plugin.pluginId)).toBeVisible({
      timeout: 60_000,
    });
  }

  await expectPluginRowVisible(
    page,
    dialog,
    installedSection,
    plugin.pluginId,
    "Installed",
  );

  await ensureInstalledPluginPolicyAllowed(page, dialog, installedSection, plugin.pluginId);

  expect(
    applyPersistedStatePin,
    `Plugin apply/reapply did not persist a current-device state pin for ${plugin.pluginId}:\n${await dialog.textContent()}`,
  ).toBe(true);

  await ensureInstalledPluginApplicationState(
    page,
    dialog,
    installedSection,
    plugin.pluginId,
    plugin.enable ?? true ? "Enabled" : "Disabled",
  );

  await returnToWorkspaceAfterPluginSettings(page);
}

export async function approvePluginUpdateFromSettings(
  page: Page,
  plugin: { fixtureName: string; pluginId: string; summaryText?: string },
): Promise<void> {
  const zipPath = buildPluginArchive(plugin.fixtureName);

  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  await expect(dialog.getByRole("heading", { name: "Community Plugins" })).toBeVisible({
    timeout: 10_000,
  });

  await dialog.getByRole("button", { name: "Upload" }).click();
  await dialog.locator('input[type="file"]').setInputFiles(zipPath);
  await reviewUploadedPlugin(page, dialog, plugin.pluginId);

  await expect(dialog.getByText(plugin.pluginId, { exact: true }).first()).toBeVisible({
    timeout: 60_000,
  });
  if (plugin.summaryText) {
    await expect(dialog.getByText(plugin.summaryText, { exact: true })).toBeVisible({
      timeout: 10_000,
    });
  }

  const approveButton = dialog.getByRole("button", { name: "Approve Plugin" });
  await expect(approveButton).toBeEnabled({ timeout: 60_000 });
  await approveButton.click();

  await expect(dialog.getByText("Plugin approved.", { exact: false })).toBeVisible({
    timeout: 90_000,
  });

  await closeSettingsDialogIfOpen(page);
}

export async function reviewUploadedPlugin(page: Page, dialog: Locator, pluginId: string): Promise<void> {
  const reviewResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/plugin-candidates$/.test(new URL(response.url()).pathname),
    { timeout: 120_000 },
  );
  await dialog.getByRole("button", { name: "Review Plugin" }).click();
  const response = await reviewResponse;
  if (response.ok()) return;
  throw new Error(
    `plugin review failed for ${pluginId}: ${response.status()} ${await response.text()}\n${await dialog.textContent()}`,
  );
}

export function buildPluginArchive(fixtureName: string, options: { version?: string } = {}): string {
  const repoRoot = path.resolve(process.cwd(), "..");
  const pluginRoot = path.join(repoRoot, "test/e2e/fixtures/plugins", fixtureName);
  const distDir = mkdtempSync(path.join(tmpdir(), `${fixtureName}-plugin-`));
  const archivePath = path.join(distDir, `${fixtureName}-plugin.zip`);
  if (options.version) {
    const manifest = JSON.parse(readFileSync(path.join(pluginRoot, "manifest.json"), "utf8")) as {
      version?: string;
    };
    manifest.version = options.version;
    writeFileSync(path.join(distDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    copyFileSync(path.join(pluginRoot, "main.js"), path.join(distDir, "main.js"));
    copyFileSync(path.join(pluginRoot, "styles.css"), path.join(distDir, "styles.css"));
    execFileSync("zip", ["-q", "-X", archivePath, "manifest.json", "main.js", "styles.css"], {
      cwd: distDir,
      stdio: "pipe",
    });
    return archivePath;
  }
  execFileSync("zip", ["-q", "-X", archivePath, "manifest.json", "main.js", "styles.css"], {
    cwd: pluginRoot,
    stdio: "pipe",
  });
  return archivePath;
}
