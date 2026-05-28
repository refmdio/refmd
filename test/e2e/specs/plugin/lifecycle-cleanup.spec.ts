import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import {
  allowPluginConsentIfPresent,
  closePluginConsentIfPresent,
  waitForPluginRuntimeApplicationWithConsent,
} from "../../support/plugin/consent";
import { savePluginCredentialFromSettings } from "../../support/plugin/credentials";
import {
  pluginRuntimeDiagnostic,
  watchPluginRuntimeFailures,
} from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import { runCommandPaletteCommand } from "../../support/plugin/editor";
import {
  collectPluginHostUiDiagnostics,
  expectUiDemoFrameRendered,
} from "../../support/plugin/host-ui";
import {
  approvePluginUpdateFromSettings,
  installPluginFromSettings,
} from "../../support/plugin/install";
import { secureLogout } from "../../support/plugin/lifecycle";
import {
  pluginLocalStatePresence,
  pluginLocalStateSnapshot,
} from "../../support/plugin/local-state";
import { configureWorkspaceNetworkProxy } from "../../support/plugin/network-rpc";
import {
  allowInstalledPluginFromSettings,
  disableInstalledPluginFromSettings,
  enableInstalledPluginFromSettings,
  removePluginActivationFromSettings,
  removePluginApplicationFromSettings,
  revokePluginConsentFromSettings,
} from "../../support/plugin/policy";
import {
  installPluginRuntimeApiCapture,
  pluginRuntimeApplicationLoaded,
} from "../../support/plugin/runtime";
import {
  closeOpenDialogOverlays,
  closeSettingsDialogIfOpen,
  getSettingsDialog,
} from "../../support/plugin/settings";
import { storageDemoFrameState } from "../../support/plugin/storage-rpc";
import {
  PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
  PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
  PLUGIN_LOCAL_STATE_CLEANUP_TIMEOUT_MS,
} from "../../support/plugin/types";
import {
  acceptWorkspaceInvitation,
  currentWorkspaceMenuLabel,
  deleteCurrentWorkspaceFromSettings,
  ensureWorkspaceSelected,
  inviteWorkspaceMember,
  leaveCurrentWorkspaceFromSettings,
} from "../../support/plugin/workspace";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import { E2E_TIMEOUTS } from "../../support/timeouts";
import {
  createWorkspace,
  switchWorkspace,
  waitForWorkspaceReady,
} from "../../support/workspace";

test("installed plugin Host UI contributions are removed after disabling the plugin", async ({
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
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Cleanup Runtime");
    await openDocument(page, "UI Demo Cleanup Runtime");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await disableInstalledPluginFromSettings(page, "io.refmd.ui-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "disabled UI demo plugin runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Cleanup Runtime" }).getByText("dt", {
        exact: true,
      }),
    ).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await openSettings(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin activation removal tears down runtime and Host UI contributions", async ({
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
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Activation Removal");
    await openDocument(page, "UI Demo Activation Removal");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await removePluginActivationFromSettings(page, "io.refmd.ui-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "deleted activation runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Activation Removal" }).getByText("dt", {
        exact: true,
      }),
    ).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await openSettings(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin application removal tears down runtime and Host UI contributions", async ({
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
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Application Removal");
    await openDocument(page, "UI Demo Application Removal");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await removePluginApplicationFromSettings(page, "io.refmd.ui-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "deleted application runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Application Removal" }).getByText("dt", {
        exact: true,
      }),
    ).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await openSettings(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin consent revoke tears down runtime and Host UI contributions", async ({
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
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Consent Revoke");
    await openDocument(page, "UI Demo Consent Revoke");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await revokePluginConsentFromSettings(page, "io.refmd.ui-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "revoked consent runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Consent Revoke" }).getByText("dt", {
        exact: true,
      }),
    ).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await openSettings(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin workspace switch tears down and resyncs Host UI contributions", async ({
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
    const sourceWorkspaceName = await currentWorkspaceMenuLabel(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Workspace Switch");
    await openDocument(page, "UI Demo Workspace Switch");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded before workspace switch",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Workspace Switch" }).getByText("dt", {
        exact: true,
      }),
    ).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await createWorkspace(page, `Plugin Switch ${Date.now()}`);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "previous workspace UI demo runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByText("UI Demo Workspace Switch", { exact: true })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await openSettings(page);
    const settingsDialog = getSettingsDialog(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await closeSettingsDialogIfOpen(page);

    await switchWorkspace(page, sourceWorkspaceName);
    await openDocument(page, "UI Demo Workspace Switch");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not reloaded after switching back",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Workspace Switch" }).getByText("dt", {
        exact: true,
      }),
    ).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin workspace delete tears down Host UI contributions", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    const sourceWorkspaceName = await currentWorkspaceMenuLabel(page);
    await createWorkspace(page, `Plugin Delete Fallback ${Date.now()}`);
    await switchWorkspace(page, sourceWorkspaceName);

    await installPluginFromSettings(page, {
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "UI Demo Workspace Delete");
    await openDocument(page, "UI Demo Workspace Delete");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded before workspace delete",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      page.locator("aside button", { hasText: "UI Demo Workspace Delete" }).getByText("dt", {
        exact: true,
      }),
    ).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await deleteCurrentWorkspaceFromSettings(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "deleted workspace UI demo runtime application remained loaded",
      })
      .toBe(false);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByText("UI Demo Workspace Delete", { exact: true })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await openSettings(page);
    const settingsDialog = getSettingsDialog(page);
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await closeSettingsDialogIfOpen(page);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin member self-leave tears down Host UI contributions", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginWorkspaceLifecycle);
  const ownerContext = await newE2EContext(browser);
  const memberContext = await newE2EContext(browser);
  await Promise.all([
    ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
    memberContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
  ]);
  const ownerPage = await ownerContext.newPage();
  const memberPage = await memberContext.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(memberPage);

  try {
    await registerAccount(ownerPage, "Plugin Owner");
    const sourceWorkspaceName = `Plugin Leave ${Date.now()}`;
    await createWorkspace(ownerPage, sourceWorkspaceName);
    await installPluginFromSettings(ownerPage, {
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
      ownerScopeKind: "workspace",
    });
    await createDocument(ownerPage, "UI Demo Member Leave");
    await openDocument(ownerPage, "UI Demo Member Leave");
    await allowPluginConsentIfPresent(ownerPage);

    const memberEmail = await registerAccount(memberPage, "Plugin Member");
    const invitationLink = await inviteWorkspaceMember(ownerPage, memberEmail);
    await acceptWorkspaceInvitation(memberPage, invitationLink);
    await ensureWorkspaceSelected(memberPage, sourceWorkspaceName);
    await closePluginConsentIfPresent(memberPage, 60_000);
    await closeOpenDialogOverlays(memberPage);
    await openDocument(memberPage, "UI Demo Member Leave");

    await allowInstalledPluginFromSettings(memberPage, "io.refmd.ui-demo");
    await enableInstalledPluginFromSettings(memberPage, "io.refmd.ui-demo");
    await memberPage.reload({ waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(memberPage);
    await openDocument(memberPage, "UI Demo Member Leave");
    await allowPluginConsentIfPresent(memberPage);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(memberPage, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded before member self-leave",
      })
      .toBe(true);
    await expect(memberPage.locator('.status-bar-item[aria-label="UI Demo Status"]'))
      .toHaveText("UI Demo Ready", { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `UI demo Host UI did not materialize before member self-leave:\nruntimeFailures=${JSON.stringify(runtimeFailures())}\n${await collectPluginHostUiDiagnostics(memberPage)}\n${String(error)}`,
        );
      });
    await expect(memberPage.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(memberPage.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(
      memberPage.locator("aside button", { hasText: "UI Demo Member Leave" }).getByText("dt", {
        exact: true,
      }),
    ).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });

    await leaveCurrentWorkspaceFromSettings(memberPage, sourceWorkspaceName);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(memberPage, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "left workspace UI demo runtime application remained loaded",
      })
      .toBe(false);
    await expect(memberPage.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(
      0,
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(memberPage.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(memberPage.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(memberPage.getByText("UI Demo Member Leave", { exact: true })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await openSettings(memberPage);
    const settingsDialog = getSettingsDialog(memberPage);
    await expect(memberPage.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(memberPage.getByRole("button", { name: "UI Demo Iframe Settings" })).toHaveCount(
      0,
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await closeSettingsDialogIfOpen(memberPage);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await memberContext.close().catch(() => {});
    await ownerContext.close().catch(() => {});
  }
});

test("installed plugin bundle update tears down old Host UI contributions before reload", async ({
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
    await createDocument(page, "UI Demo Bundle Update");
    await openDocument(page, "UI Demo Bundle Update");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.ui-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "UI demo plugin runtime application was not loaded before bundle update",
      })
      .toBe(true);
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveText(
      "UI Demo Ready",
      { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS },
    );
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await approvePluginUpdateFromSettings(page, {
      fixtureName: "refmd-ui-demo-update",
      pluginId: "io.refmd.ui-demo",
    });

    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await allowInstalledPluginFromSettings(page, "io.refmd.ui-demo");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.ui-demo", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      message: "updated UI demo plugin runtime application was not loaded",
      extraDiagnostic: runtimeApiCapture.summary,
    });
    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status V2"]'))
      .toHaveText("UI Demo V2 Ready", { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `updated UI demo status contribution did not render:\nruntimeFailures=${JSON.stringify(
            runtimeFailures(),
          )}\nruntimeApi=${runtimeApiCapture.summary()}\n${await collectPluginHostUiDiagnostics(
            page,
          )}\n${String(error)}`,
        );
      });
    await expectUiDemoFrameRendered(page, "UI Demo Status Frame V2", {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
      runtimeFailures,
      runtimeApi: runtimeApiCapture.summary,
    });
    await expect(page.getByRole("button", { name: "UI Demo Sidebar V2" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Tree Section V2" })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });

    await openSettings(page);
    await selectSettingsTab(page, "UI Demo Settings V2");
    const settingsDialog = getSettingsDialog(page);
    await expect(settingsDialog.getByText("UI Demo Controls V2", { exact: true })).toBeVisible({
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expect(page.getByRole("button", { name: "UI Demo Settings" })).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await closeSettingsDialogIfOpen(page);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin secure logout clears runtime and local plugin data", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginWorkspaceLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const proxyRequests: Array<Record<string, unknown>> = [];
  let directTargetRequests = 0;

  await page.route("https://api.refmd-e2e.example/**", async (route) => {
    directTargetRequests += 1;
    await route.abort("blockedbyclient");
  });
  await page.route("https://proxy.example/refmd", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}") as Record<string, unknown>;
    proxyRequests.push(body);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "Access-Control-Allow-Origin": "*" },
      body: JSON.stringify({
        status: 200,
        headers: { "content-type": "application/json" },
        body_text: "credential-demo-response",
      }),
    });
  });

  try {
    await registerAccount(page);
    await configureWorkspaceNetworkProxy(page, "credential-demo-api");

    await installPluginFromSettings(page, {
      fixtureName: "refmd-credential-demo",
      pluginId: "io.refmd.credential-demo",
      summaryText: "credential:use",
      enable: false,
    });
    await savePluginCredentialFromSettings(page, "io.refmd.credential-demo");
    await allowInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await enableInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await createDocument(page, "Secure Logout Plugin Cleanup");
    await openDocument(page, "Secure Logout Plugin Cleanup");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not loaded before secure logout",
    });
    const credentialStatus = page.locator('.status-bar-item[aria-label="Handle Demo Status"]');
    expect(directTargetRequests).toBe(0);

    await installPluginFromSettings(page, {
      fixtureName: "refmd-storage-demo",
      pluginId: "io.refmd.storage-demo",
    });
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.storage-demo", {
      timeout: 180_000,
      message: "storage demo plugin runtime application was not loaded before secure logout",
    });
    const storageStatus = page.locator('.status-bar-item[aria-label="Storage Demo Status"]');
    await expect(storageStatus).toHaveText("Storage Demo Ready", { timeout: 90_000 });
    await runCommandPaletteCommand(page, "Storage Demo Write Values");
    await expect(storageStatus)
      .toHaveText("STORAGE_WRITE_OK", { timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS })
      .catch(async (error) => {
        throw new Error(
          `secure logout storage write command did not update Host status:\nstate=${JSON.stringify(
            await storageDemoFrameState(page),
          )}\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`,
        );
      });
    await runCommandPaletteCommand(page, "Storage Demo Read Values");
    await expect(storageStatus).toContainText("STORAGE_READ_OK: true", {
      timeout: PLUGIN_COMMAND_STATUS_TIMEOUT_MS,
    });

    await expect
      .poll(() => pluginLocalStatePresence(page), {
        timeout: 30_000,
        message: "browser-local plugin DSK state was not created before secure logout",
      })
      .toEqual({
        cache: true,
        credential: true,
        databaseApiUnavailable: false,
        userLocal: true,
      });

    expect(runtimeFailures()).toEqual([]);

    await secureLogout(page);

    await expect(storageStatus).toHaveCount(0, { timeout: 30_000 });
    await expect(credentialStatus).toHaveCount(0, { timeout: 30_000 });
    await expect.poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.storage-demo"), {
      timeout: 30_000,
      message: "storage demo runtime remained loaded after secure logout",
    }).toBe(false);
    await expect.poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.credential-demo"), {
      timeout: 30_000,
      message: "credential demo runtime remained loaded after secure logout",
    }).toBe(false);
    await expect(page.locator("iframe")).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginLocalStateSnapshot(page), {
        timeout: PLUGIN_LOCAL_STATE_CLEANUP_TIMEOUT_MS,
        message: "secure logout did not remove browser-local plugin and crypto stores",
      })
      .toEqual({
        databaseApiUnavailable: false,
        dbNames: expect.not.arrayContaining([
          "refmd-keys",
          "refmd-trust",
          "refmd-offline",
          "refmd-security",
          "refmd-share-sessions",
        ]),
        errors: [],
        pluginKeys: [],
        targetDbNames: [],
      });
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
