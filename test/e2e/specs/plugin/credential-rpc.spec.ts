import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import {
  allowPluginConsentIfPresent,
  waitForPluginRuntimeApplicationWithConsent,
} from "../../support/plugin/consent";
import {
  credentialDemoFrameState,
  savePluginCredentialFromSettings,
} from "../../support/plugin/credentials";
import {
  pluginRuntimeDiagnostic,
  watchPluginRuntimeFailures,
} from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import {
  expectCommandPaletteCommandAbsent,
  runCommandPaletteCommand,
} from "../../support/plugin/editor";
import { installPluginFromSettings } from "../../support/plugin/install";
import { configureWorkspaceNetworkProxy } from "../../support/plugin/network-rpc";
import {
  allowInstalledPluginFromSettings,
  enableInstalledPluginFromSettings,
  reapplyInstalledPluginFromSettings,
  removePluginActivationFromSettings,
  removePluginApplicationFromSettings,
} from "../../support/plugin/policy";
import {
  installPluginRuntimeApiCapture,
  pluginRuntimeApplicationLoaded,
} from "../../support/plugin/runtime";
import { returnToWorkspaceAfterPluginSettings } from "../../support/plugin/settings";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("installed plugin credential handle is issued by Host UI and used through proxy fetch", async ({
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
    await enableInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await createDocument(page, "Credential Demo Plugin Runtime");
    await openDocument(page, "Credential Demo Plugin Runtime");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not loaded",
    });
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 90_000,
        message: "credential demo plugin sandbox did not register credential command",
      })
      .toEqual(expect.objectContaining({ status: "Handle command registered" }));
    const status = page.locator('.status-bar-item[aria-label="Handle Demo Status"]');
    await expect(status).toHaveText("Handle Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Handle Demo Run");
    await expect(status).toContainText("HANDLE_OK: true", { timeout: 60_000 });
    await expect(status).toContainText("secretVisible=false", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive the credential-bound Host request envelope",
      })
      .toBe(1);
    expect(directTargetRequests).toBe(0);
    expect(proxyRequests[0]).toEqual(
      expect.objectContaining({
        protocol: "refmd.plugin-network-proxy-request",
        version: 1,
        subject: expect.objectContaining({
          target: expect.objectContaining({
            url: "https://api.refmd-e2e.example/v1/credential-demo",
            method: "POST",
            headers: expect.objectContaining({
              authorization: "Bearer refmd-e2e-secret",
            }),
          }),
          endpoint: expect.objectContaining({
            id: "credential-demo-api",
            credential_audience: "api.refmd-e2e.example",
          }),
          runtime: expect.objectContaining({
            credential_handle_used: true,
          }),
        }),
      }),
    );

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin credential destructive cleanup removes persisted Host credential", async ({
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
    await returnToWorkspaceAfterPluginSettings(page);
    await createDocument(page, "Credential Demo Destructive Cleanup");
    await allowInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await enableInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await openDocument(page, "Credential Demo Destructive Cleanup");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not loaded before cleanup",
    });
    const status = page.locator('.status-bar-item[aria-label="Handle Demo Status"]');
    await expect(status).toHaveText("Handle Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Handle Demo Run");
    await expect(status).toContainText("HANDLE_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive initial credential-bound request",
      })
      .toBe(1);
    expect(directTargetRequests).toBe(0);

    await removePluginApplicationFromSettings(page, "io.refmd.credential-demo");
    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expectCommandPaletteCommandAbsent(page, "Handle Demo Run");
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.credential-demo"), {
        timeout: 90_000,
        message: "credential demo runtime remained loaded after application deletion",
      })
      .toBe(false);

    proxyRequests.length = 0;
    directTargetRequests = 0;

    await installPluginFromSettings(page, {
      fixtureName: "refmd-credential-demo",
      pluginId: "io.refmd.credential-demo",
      summaryText: "credential:use",
      manifestVersion: "0.1.1",
    });
    await allowInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await openDocument(page, "Credential Demo Destructive Cleanup");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not reloaded after destructive cleanup",
      extraDiagnostic: runtimeApiCapture.summary,
    });
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 120_000,
        message: "credential demo plugin sandbox did not re-register credential command",
      })
      .toEqual(expect.objectContaining({ status: "Handle command registered" }))
      .catch(async (error) => {
        throw new Error(
          `credential demo plugin sandbox did not re-register credential command:\nstate=${JSON.stringify(
            await credentialDemoFrameState(page),
          )}\n${await pluginRuntimeDiagnostic(page)}\n${runtimeApiCapture.summary()}\n${String(error)}`,
        );
      });
    await expect(status).toHaveText("Handle Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Handle Demo Run");
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 60_000,
        message: "credential cleanup failure result did not reach the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("credential_not_found") }));
    await expect(status).toContainText("Handle failed: missing handle", { timeout: 60_000 });
    expect(proxyRequests).toHaveLength(0);
    expect(directTargetRequests).toBe(0);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin credential activation deletion cleanup removes persisted Host credential", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.recoveryWithPlugin);
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
    await returnToWorkspaceAfterPluginSettings(page);
    await createDocument(page, "Credential Demo Activation Cleanup");
    await allowInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await enableInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await openDocument(page, "Credential Demo Activation Cleanup");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not loaded before activation cleanup",
    });
    const status = page.locator('.status-bar-item[aria-label="Handle Demo Status"]');
    await expect(status).toHaveText("Handle Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Handle Demo Run");
    await expect(status).toContainText("HANDLE_OK: true", { timeout: 60_000 });
    await expect
      .poll(() => proxyRequests.length, {
        timeout: 30_000,
        message: "external proxy did not receive initial credential-bound request",
      })
      .toBe(1);
    expect(directTargetRequests).toBe(0);

    await removePluginActivationFromSettings(page, "io.refmd.credential-demo");
    await expect(status).toHaveCount(0, { timeout: 30_000 });
    await expectCommandPaletteCommandAbsent(page, "Handle Demo Run");
    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.credential-demo"), {
        timeout: 90_000,
        message: "credential demo runtime remained loaded after activation deletion",
      })
      .toBe(false);
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 30_000,
        message: "credential demo sandbox frame remained after activation deletion",
      })
      .toEqual(expect.objectContaining({ frameCount: 0 }));

    proxyRequests.length = 0;
    directTargetRequests = 0;

    await reapplyInstalledPluginFromSettings(page, "io.refmd.credential-demo");
    await openDocument(page, "Credential Demo Activation Cleanup");
    await allowPluginConsentIfPresent(page, 30_000);
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.credential-demo", {
      timeout: 180_000,
      message: "credential demo plugin runtime application was not reloaded after activation cleanup",
      extraDiagnostic: runtimeApiCapture.summary,
    });
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 120_000,
        message: "credential demo plugin sandbox did not re-register credential command",
      })
      .toEqual(expect.objectContaining({ status: "Handle command registered" }))
      .catch(async (error) => {
        throw new Error(
          `credential demo plugin sandbox did not re-register credential command:\nstate=${JSON.stringify(
            await credentialDemoFrameState(page),
          )}\n${await pluginRuntimeDiagnostic(page)}\n${runtimeApiCapture.summary()}\n${String(error)}`,
        );
      });
    await expect(status).toHaveText("Handle Demo Ready", { timeout: 90_000 });

    await runCommandPaletteCommand(page, "Handle Demo Run");
    await expect
      .poll(() => credentialDemoFrameState(page), {
        timeout: 60_000,
        message: "credential activation cleanup failure result did not reach the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("credential_not_found") }));
    await expect(status).toContainText("Handle failed: missing handle", { timeout: 60_000 });
    expect(proxyRequests).toHaveLength(0);
    expect(directTargetRequests).toBe(0);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
