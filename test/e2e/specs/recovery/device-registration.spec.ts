import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import {
  TEST_PASSWORD,
  testEmail,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import {
  safePageFrames,
  pluginRuntimeDiagnostic,
  watchPluginRuntimeFailures,
} from "../../support/plugin/diagnostics";
import { allowPluginConsentIfPresent } from "../../support/plugin/consent";
import { installDemoPluginFromSettings } from "../../support/plugin/install";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

async function registerAccountAndReadRecoveryPhrase(page: Page): Promise<{
  email: string;
  mnemonic: string;
}> {
  const email = testEmail();

  await page.goto("/auth/register");
  await expect(page.locator("#name")).toBeVisible({ timeout: 60_000 });
  await page.locator("#name").fill("E2E Recovery User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });
  await page.getByRole("button", { name: "Show" }).click();

  const words = await page
    .locator("div.grid.grid-cols-3 > div > span:nth-child(2)")
    .allTextContents();
  expect(words).toHaveLength(24);
  const mnemonic = words.join(" ");

  await page.getByRole("button", { name: "Download" }).click();
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });

  await expect(page).toHaveURL(/dashboard/, { timeout: 20_000 });
  await waitForWorkspaceReady(page);

  return { email, mnemonic };
}

async function loginForDeviceRegistration(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });
  await expect(page.getByRole("link", { name: "use your recovery key" })).toBeVisible({
    timeout: 60_000,
  });
}

async function recoverDeviceWithMnemonic(
  page: Page,
  email: string,
  mnemonic: string,
  documentTitle: string,
  options: {
    afterRecovery?: (page: Page) => Promise<void>;
    afterReload?: (page: Page) => Promise<void>;
    openRecoveredDocument?: (page: Page, title: string) => Promise<void>;
  } = {},
): Promise<void> {
  let normalChallengeRequests = 0;
  let normalRegistrationRequests = 0;
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    const pathname = new URL(request.url()).pathname;
    if (pathname.endsWith("/devices/registrations/challenge")) normalChallengeRequests += 1;
    if (pathname.endsWith("/devices/registrations")) normalRegistrationRequests += 1;
  });
  await loginForDeviceRegistration(page, email);

  await page.getByRole("link", { name: "use your recovery key" }).click();
  await expect(page).toHaveURL(/\/auth\/recovery/, { timeout: 30_000 });
  await page.locator('input[placeholder="word"]').first().fill(mnemonic);
  await page.getByRole("button", { name: "Recover Account" }).click();

  await expect(page).toHaveURL(/dashboard/, { timeout: 180_000 });
  await waitForWorkspaceReady(page);
  expect(normalChallengeRequests).toBe(0);
  expect(normalRegistrationRequests).toBe(0);
  await options.afterRecovery?.(page);

  const errors = await collectErrors(page, async () => {
    await (options.openRecoveredDocument ?? openDocument)(page, documentTitle);
  });
  expect(errors.join("\n")).not.toContain("rrp_device_session_mismatch");
  expect(errors.join("\n")).not.toContain("Channel join failed");
  await expect(page.locator(".cm-content, .ProseMirror").first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByText("rrp_device_session_mismatch")).not.toBeVisible({
    timeout: 1_000,
  });
  await expect(page.getByText("Channel join failed")).not.toBeVisible({
    timeout: 1_000,
  });

  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
  expect(page.url()).not.toMatch(/\/devices\/register/);
  await options.afterReload?.(page);
  const editor = page.locator(".cm-content, .ProseMirror").first();
  const reloadErrors = await collectErrors(page, async () => {
    if (await editor.isVisible({ timeout: 1_000 }).catch(() => false)) return;
    await (options.openRecoveredDocument ?? openDocument)(page, documentTitle);
  });
  expect(reloadErrors.join("\n")).not.toContain("rrp_device_session_mismatch");
  expect(reloadErrors.join("\n")).not.toContain("Channel join failed");
  await expect(editor).toBeVisible({ timeout: 60_000 });
}

async function openDocumentAllowingPluginConsent(page: Page, title: string): Promise<void> {
  await waitForWorkspaceReady(page);
  const button = page.locator("aside").getByRole("button", { name: title });
  const row = page.locator("aside").getByText(title, { exact: true }).first();
  const editor = page.locator(".cm-content, .ProseMirror").first();
  const deadline = Date.now() + 120_000;
  let lastState: unknown = null;
  let documentOpened = /\/document\//.test(page.url());

  while (Date.now() < deadline) {
    const panelCount = await page.locator("[data-panel-id]").count().catch(() => 0);
    documentOpened = documentOpened || panelCount > 0 || /\/document\//.test(page.url());

    if (!documentOpened) {
      if (await button.isVisible({ timeout: 500 }).catch(() => false)) {
        await button.click({ timeout: 5_000 });
      } else {
        await expect(row).toBeVisible({ timeout: 60_000 });
        await row.click({ timeout: 5_000 });
      }
    }

    await allowPluginConsentIfPresent(page, 5_000);
    if (await editor.isVisible({ timeout: 500 }).catch(() => false)) return;
    lastState = await page.evaluate(() => ({
      bodySnippet: document.body.textContent?.slice(0, 500) ?? "",
      clientLogs: (window.__refmdE2EClientLogs ?? []).slice(-10),
      dialogs: Array.from(document.querySelectorAll('[role="dialog"]')).map((node) =>
        node.textContent?.replace(/\s+/g, " ").trim(),
      ),
      panelCount: document.querySelectorAll("[data-panel-id]").length,
      syncState: window.__refmdGetDocumentSyncState?.(
        new URL(location.href).pathname.match(/\/document\/([^/]+)/)?.[1] ?? "",
      ),
      url: window.location.href,
    }));
    await page.waitForTimeout(E2E_DELAYS.poll);
  }

  throw new Error(
    `editor did not mount after opening ${title} with plugin consent handling:\n${JSON.stringify(
      lastState,
    )}\n${await pluginRuntimeDiagnostic(page)}`,
  );
}

async function waitForDemoPluginRuntimeState(page: Page): Promise<void> {
  await page
    .waitForFunction(
      () => {
        const debug = window.__refmdPluginRuntimeDebug;
        const application =
          debug?.applications.some((entry) => entry.pluginId === "io.refmd.renderer-demo") === true;
        const blockRendererSlot =
          debug?.rendererRegistry.some(
            (entry) =>
              entry.pluginId === "io.refmd.renderer-demo" &&
              entry.slots.some(
                (slot) => slot.kind === "block" && slot.type === "refmd-renderer-demo",
              ),
          ) === true;
        const inlineRendererSlot =
          debug?.rendererRegistry.some(
            (entry) =>
              entry.pluginId === "io.refmd.renderer-demo" &&
              entry.slots.some((slot) => slot.kind === "inline" && slot.type === "code"),
          ) === true;
        return application && blockRendererSlot && inlineRendererSlot;
      },
      undefined,
      { timeout: 120_000 },
    )
    .catch(async (error) => {
      throw new Error(
        `recovered device never exposed the installed plugin runtime registry:\n${await pluginRuntimeDiagnostic(
          page,
        )}\n${String(error)}`,
      );
    });
}

async function currentDocumentId(page: Page): Promise<string> {
  const match = new URL(page.url()).pathname.match(/\/document\/([^/]+)/);
  if (match?.[1]) return match[1];
  const appDocumentId = await page.evaluate(() => {
    const app = (
      window as Window & {
        __REFMD_APP_INSTANCE__?: {
          documents?: {
            getDocumentList?: () => Array<{ id: string }>;
            getActiveDocument?: () => { id: string } | null;
          };
        };
      }
    ).__REFMD_APP_INSTANCE__;
    const activeDocumentId = app?.documents?.getActiveDocument?.()?.id;
    if (activeDocumentId) return activeDocumentId;
    const documents = app?.documents?.getDocumentList?.() ?? [];
    return documents.length === 1 ? documents[0].id : null;
  });
  if (!appDocumentId) throw new Error(`document id not found in URL or app state: ${page.url()}`);
  return appDocumentId;
}

async function replaceEditorMarkdown(page: Page, markdown: string): Promise<void> {
  const documentId = await currentDocumentId(page);
  await page
    .waitForFunction(
      ([id, value]) => window.__refmdSetEditorValueForDocument?.(id, value) === true,
      [documentId, markdown] as const,
      { timeout: 60_000 },
    )
    .catch(async (error) => {
      throw new Error(
        `document editor test hook did not accept the markdown value:\n${await pluginRuntimeDiagnostic(
          page,
        )}\n${String(error)}`,
      );
    });
  await expectEditorTextContains(page, "```refmd-renderer-demo", 30_000);
}

async function demoPluginFrameState(
  page: Page,
  sandboxResponses: string[],
): Promise<{
  mounted: boolean;
  kind: string | null;
  type: string | null;
  source: string | null;
  slotCount: number;
  frameTexts: string[];
  frameUrls: string[];
  sandboxResponses: string[];
}> {
  const selector =
    '.refmd-plugin-renderer-slot[data-renderer-kind="block"][data-renderer-type="refmd-renderer-demo"]';
  const slot = page.locator(selector).first();
  const slotCount = await page.locator(selector).count().catch(() => 0);
  const frameTexts: string[] = [];
  const frameUrls: string[] = [];
  for (const frame of safePageFrames(page)) {
    frameUrls.push(frame.url());
    const text = await frame.locator("body").innerText({ timeout: 500 }).catch(() => "");
    if (text.includes("RefMD Renderer Demo Plugin")) frameTexts.push(text.slice(0, 200));
  }
  if (!(await slot.isVisible({ timeout: 1_000 }).catch(() => false))) {
    return {
      mounted: false,
      kind: null,
      type: null,
      source: null,
      slotCount,
      frameTexts,
      frameUrls,
      sandboxResponses,
    };
  }
  const frameHandle = await slot.locator("iframe").elementHandle({ timeout: 1_000 }).catch(() => null);
  const frame = await frameHandle?.contentFrame();
  if (!frame) {
    return {
      mounted: false,
      kind: null,
      type: null,
      source: null,
      slotCount,
      frameTexts,
      frameUrls,
      sandboxResponses,
    };
  }
  const text = await frame.locator("body").innerText({ timeout: 1_000 }).catch(() => "");
  return {
    mounted:
      text.includes("RefMD Renderer Demo Plugin") &&
      text.includes("Renderer Invocation") &&
      text.includes("Mounted"),
    kind: await frame.locator('[data-role="kind"]').textContent({ timeout: 500 }).catch(() => null),
    type: await frame.locator('[data-role="type"]').textContent({ timeout: 500 }).catch(() => null),
    source: await frame.locator('[data-role="source"]').textContent({ timeout: 500 }).catch(() => null),
    slotCount,
    frameTexts,
    frameUrls,
    sandboxResponses,
  };
}

function watchSandboxDocumentResponses(page: Page): () => string[] {
  const responses: string[] = [];
  page.on("response", (response) => {
    if (!response.url().includes("sandbox-documents")) return;
    const headers = response.headers();
    responses.push(
      [
        response.status(),
        response.url(),
        headers["content-type"] ?? "",
        headers["content-security-policy"] ?? "",
      ].join(" "),
    );
  });
  return () => responses.slice(-8);
}

test.describe("Recovery device registration", () => {
  let ownerContext: BrowserContext;
  let recoveryContext: BrowserContext;
  let secondRecoveryContext: BrowserContext;

  test.afterEach(async () => {
    await secondRecoveryContext?.close().catch(() => {});
    await recoveryContext?.close().catch(() => {});
    await ownerContext?.close().catch(() => {});
  });

  test("recovers a new device with the 24-word recovery phrase", async ({ browser }) => {
    test.setTimeout(E2E_TIMEOUTS.multiDevice);

    ownerContext = await newE2EContext(browser);
    const ownerPage = await ownerContext.newPage();
    const { email, mnemonic } = await registerAccountAndReadRecoveryPhrase(ownerPage);
    const documentTitle = `Recovery Channel Join ${Date.now()}`;
    await createDocument(ownerPage, documentTitle);

    recoveryContext = await newE2EContext(browser);
    const recoveryPage = await recoveryContext.newPage();
    await recoverDeviceWithMnemonic(recoveryPage, email, mnemonic, documentTitle);

    secondRecoveryContext = await newE2EContext(browser);
    const secondRecoveryPage = await secondRecoveryContext.newPage();
    await recoverDeviceWithMnemonic(secondRecoveryPage, email, mnemonic, documentTitle);
  });

  test("recovered device starts an installed community plugin runtime", async ({ browser }) => {
    test.setTimeout(E2E_TIMEOUTS.recoveryWithPlugin);

    ownerContext = await newE2EContext(browser);
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    const ownerPage = await ownerContext.newPage();
    const { email, mnemonic } = await registerAccountAndReadRecoveryPhrase(ownerPage);
    const documentTitle = `Recovery Plugin Runtime ${Date.now()}`;
    await createDocument(ownerPage, documentTitle);
    await installDemoPluginFromSettings(ownerPage);

    recoveryContext = await newE2EContext(browser);
    await recoveryContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    const recoveryPage = await recoveryContext.newPage();
    const runtimeFailures = await watchPluginRuntimeFailures(recoveryPage);
    const sandboxResponses = watchSandboxDocumentResponses(recoveryPage);

    await recoverDeviceWithMnemonic(recoveryPage, email, mnemonic, documentTitle, {
      afterRecovery: (page) => allowPluginConsentIfPresent(page, 1_000),
      afterReload: (page) => allowPluginConsentIfPresent(page, 5_000),
      openRecoveredDocument: openDocumentAllowingPluginConsent,
    });
    await waitForDemoPluginRuntimeState(recoveryPage);
    await replaceEditorMarkdown(
      recoveryPage,
      "# Recovery Plugin Runtime\n\n```refmd-renderer-demo\nrecovered-device-block\n```",
    );
    await allowPluginConsentIfPresent(recoveryPage);

    await expect
      .poll(() => demoPluginFrameState(recoveryPage, sandboxResponses()), {
        timeout: 120_000,
        message: "recovered device did not mount the installed plugin renderer iframe",
      })
      .toEqual(
        expect.objectContaining({
          mounted: true,
          kind: "block",
          type: "refmd-renderer-demo",
          source: "recovered-device-block",
        }),
      );
    expect(runtimeFailures()).toEqual([]);
  });
});
