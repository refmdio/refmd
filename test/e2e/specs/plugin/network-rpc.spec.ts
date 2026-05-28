import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import {
  allowPluginConsentIfPresent,
  waitForPluginRuntimeApplicationWithConsent,
} from "../../support/plugin/consent";
import { watchPluginRuntimeFailures } from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import {
  expectCommandPaletteCommandAbsent,
  runCommandPaletteCommand,
} from "../../support/plugin/editor";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  configureWorkspaceNetworkProxy,
  networkDemoFrameState,
} from "../../support/plugin/network-rpc";
import {
  removePluginActivationFromSettings,
  removePluginApplicationFromSettings,
  revokePluginConsentFromSettings,
} from "../../support/plugin/policy";
import {
  installPluginRuntimeApiCapture,
  pluginRuntimeApplicationLoaded,
} from "../../support/plugin/runtime";
import { PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS } from "../../support/plugin/types";
import { currentWorkspaceMenuLabel } from "../../support/plugin/workspace";
import { E2E_TIMEOUTS } from "../../support/timeouts";
import {
  createWorkspace,
  switchWorkspace,
} from "../../support/workspace";

test("installed plugin network proxy fetch runs through Host RPC and Host proxy settings", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const runtimeApiCapture = installPluginRuntimeApiCapture(page);
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
        body_text: "network-demo-response",
      }),
    });
  });

  try {
    await registerAccount(page);
    await configureWorkspaceNetworkProxy(page);
    await createDocument(page, "Network Demo Plugin Runtime");
    await installPluginFromSettings(page, {
      fixtureName: "refmd-network-demo",
      pluginId: "io.refmd.network-demo",
    });
    await openDocument(page, "Network Demo Plugin Runtime");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not loaded",
    });
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin sandbox did not register network commands",
      })
      .toEqual(expect.objectContaining({ status: "Network commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Network Demo Status"]');
    await expect(status).toHaveText("Network Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Network Demo Proxy Fetch");
    await expect(status).toContainText("NETWORK_PROXY_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive the Host-signed request envelope",
      })
      .toBe(1);
    expect(directTargetRequests).toBe(0);
    expect(proxyRequests[0]).toEqual(
      expect.objectContaining({
        protocol: "refmd.plugin-network-proxy-request",
        version: 1,
        subject: expect.objectContaining({
          proxy: expect.objectContaining({
            id: "workspace-proxy",
            origin: "https://proxy.example/refmd",
          }),
          target: expect.objectContaining({
            url: "https://api.refmd-e2e.example/v1/network-demo",
            method: "POST",
          }),
          endpoint: expect.objectContaining({
            id: "network-demo-api",
          }),
          runtime: expect.objectContaining({
            credential_handle_used: false,
          }),
        }),
      }),
    );

    await runCommandPaletteCommand(page, "Network Demo Rejected Routes");
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin did not report rejected route results",
      })
      .toEqual(
        expect.objectContaining({
          status: expect.stringContaining("NETWORK_REJECT_OK: true"),
        }),
      );
    const rejectState = await networkDemoFrameState(page);
    expect(rejectState.status).toContain("network_route_unavailable");
    expect(rejectState.status).toContain("plugin_proxy_forbidden");
    expect(proxyRequests).toHaveLength(1);
    expect(directTargetRequests).toBe(0);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin network application removal clears runtime and commands", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const runtimeApiCapture = installPluginRuntimeApiCapture(page);
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
        body_text: "network-demo-response",
      }),
    });
  });

  try {
    await registerAccount(page);
    await configureWorkspaceNetworkProxy(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-network-demo",
      pluginId: "io.refmd.network-demo",
    });
    await createDocument(page, "Network Demo Application Removal");
    await openDocument(page, "Network Demo Application Removal");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not loaded before application removal",
    });
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin sandbox did not register network commands",
      })
      .toEqual(expect.objectContaining({ status: "Network commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Network Demo Status"]');
    await expect(status).toHaveText("Network Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Network Demo Proxy Fetch");
    await expect(status).toContainText("NETWORK_PROXY_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive the Host-signed request envelope before removal",
      })
      .toBe(1);

    await removePluginApplicationFromSettings(page, "io.refmd.network-demo");

    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.network-demo"), {
        timeout: 90_000,
        message: "deleted network demo application runtime remained loaded",
      })
      .toBe(false);
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 30_000,
        message: "network demo sandbox frame remained after application deletion",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));
    await expect(page.locator('iframe[data-refmd-plugin-network-executor="true"]')).toHaveCount(0, {
      timeout: 30_000,
    });
    await expectCommandPaletteCommandAbsent(page, "Network Demo Proxy Fetch");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Rejected Routes");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Pending Fetch");

    expect(proxyRequests).toHaveLength(1);
    expect(directTargetRequests).toBe(0);
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin network consent revoke clears runtime and commands", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
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
        body_text: "network-demo-response",
      }),
    });
  });

  try {
    await registerAccount(page);
    await configureWorkspaceNetworkProxy(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-network-demo",
      pluginId: "io.refmd.network-demo",
    });
    await createDocument(page, "Network Demo Consent Revoke");
    await openDocument(page, "Network Demo Consent Revoke");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not loaded before consent revoke",
    });
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin sandbox did not register network commands before consent revoke",
      })
      .toEqual(expect.objectContaining({ status: "Network commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Network Demo Status"]');
    await expect(status).toHaveText("Network Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Network Demo Proxy Fetch");
    await expect(status).toContainText("NETWORK_PROXY_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive the Host-signed request envelope before consent revoke",
      })
      .toBe(1);

    await revokePluginConsentFromSettings(page, "io.refmd.network-demo");

    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.network-demo"), {
        timeout: 90_000,
        message: "revoked network demo consent runtime remained loaded",
      })
      .toBe(false);
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 30_000,
        message: "network demo sandbox frame remained after consent revoke",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));
    await expect(page.locator('iframe[data-refmd-plugin-network-executor="true"]')).toHaveCount(0, {
      timeout: 30_000,
    });
    await expectCommandPaletteCommandAbsent(page, "Network Demo Proxy Fetch");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Rejected Routes");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Pending Fetch");

    expect(proxyRequests).toHaveLength(1);
    expect(directTargetRequests).toBe(0);
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin network workspace switch clears runtime and commands", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
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
        body_text: "network-demo-response",
      }),
    });
  });

  try {
    await registerAccount(page);
    const sourceWorkspaceName = await currentWorkspaceMenuLabel(page);
    await configureWorkspaceNetworkProxy(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-network-demo",
      pluginId: "io.refmd.network-demo",
    });
    await createDocument(page, "Network Demo Workspace Switch");
    await openDocument(page, "Network Demo Workspace Switch");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not loaded before workspace switch",
    });
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin sandbox did not register network commands before workspace switch",
      })
      .toEqual(expect.objectContaining({ status: "Network commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Network Demo Status"]');
    await expect(status).toHaveText("Network Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Network Demo Proxy Fetch");
    await expect(status).toContainText("NETWORK_PROXY_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive the Host-signed request envelope before workspace switch",
      })
      .toBe(1);

    await createWorkspace(page, `Network Plugin Switch ${Date.now()}`);

    await expect(status).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.network-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "previous workspace network demo runtime remained loaded",
      })
      .toBe(false);
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "network demo sandbox frame remained after workspace switch",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));
    await expect(page.locator('iframe[data-refmd-plugin-network-executor="true"]')).toHaveCount(0, {
      timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
    });
    await expectCommandPaletteCommandAbsent(page, "Network Demo Proxy Fetch");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Rejected Routes");
    await expectCommandPaletteCommandAbsent(page, "Network Demo Pending Fetch");

    await switchWorkspace(page, sourceWorkspaceName);
    await openDocument(page, "Network Demo Workspace Switch");
    await allowPluginConsentIfPresent(page);

    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not reloaded after switching back",
    });
    await expect(page.locator('.status-bar-item[aria-label="Network Demo Status"]')).toHaveText(
      "Network Demo Ready",
      { timeout: 90_000 },
    );

    expect(proxyRequests).toHaveLength(1);
    expect(directTargetRequests).toBe(0);
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin pending network RPC closes on activation removal", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  let directTargetRequests = 0;
  let stalledProxyRequests = 0;

  await page.route("https://api.refmd-e2e.example/**", async (route) => {
    directTargetRequests += 1;
    await route.abort("blockedbyclient");
  });
  await page.route("https://proxy.example/refmd", async (route) => {
    stalledProxyRequests += 1;
    await new Promise((resolve) => setTimeout(resolve, 15_000));
    await route
      .fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Access-Control-Allow-Origin": "*" },
        body: JSON.stringify({
          status: 200,
          headers: { "content-type": "application/json" },
          body_text: "network-demo-response",
        }),
      })
      .catch(() => {});
  });

  try {
    await registerAccount(page);
    await configureWorkspaceNetworkProxy(page, "network-demo-api");
    await installPluginFromSettings(page, {
      fixtureName: "refmd-network-demo",
      pluginId: "io.refmd.network-demo",
    });
    await createDocument(page, "Network Demo Pending Cleanup");
    await openDocument(page, "Network Demo Pending Cleanup");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.network-demo", {
      timeout: 180_000,
      message: "network demo plugin runtime application was not loaded before pending cleanup",
    });
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 90_000,
        message: "network demo plugin sandbox did not register network commands",
      })
      .toEqual(expect.objectContaining({ status: "Network commands registered" }));
    const status = page.locator('.status-bar-item[aria-label="Network Demo Status"]');
    await expect(status).toHaveText("Network Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Network Demo Pending Fetch");
    await expect(status).toHaveText("NETWORK_PENDING_STARTED", { timeout: 30_000 });
    await expect
      .poll(() => stalledProxyRequests, {
        timeout: 30_000,
        message: "pending proxy request was not started before application removal",
      })
      .toBe(1);
    await expect(page.locator('iframe[data-refmd-plugin-network-executor="true"]')).toHaveCount(1, {
      timeout: 10_000,
    });

    await removePluginActivationFromSettings(page, "io.refmd.network-demo");
    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.network-demo"), {
        timeout: 90_000,
        message: "network demo runtime remained loaded after pending activation deletion",
      })
      .toBe(false);
    await expect
      .poll(() => networkDemoFrameState(page), {
        timeout: 30_000,
        message: "network demo sandbox frame remained after pending activation deletion",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));
    await expect(page.locator('iframe[data-refmd-plugin-network-executor="true"]')).toHaveCount(0, {
      timeout: 30_000,
    });
    expect(directTargetRequests).toBe(0);
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
