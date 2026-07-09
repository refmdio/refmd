import { expect, test, type Page } from "@playwright/test";
import {
  TEST_PASSWORD,
  registerAccount,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

async function loginForDeviceRegistration(page: Page, email: string) {
  await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });
}

async function waitForSyncReady(page: Page, documentId: string, label: string) {
  const states: unknown[] = [];
  await expect
    .poll(
      async () => {
        const state = await page.evaluate(
          (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
          documentId,
        );
        states.push(state);
        return state;
      },
      {
        timeout: 90_000,
        message: `${label} did not become sync-ready: ${JSON.stringify(states)}`,
      },
    )
    .toMatchObject({
      channelState: "joined",
      error: null,
      initialized: true,
      reconnecting: false,
      syncPaused: false,
    });
}

async function typeLineBurst(
  page: Page,
  documentId: string,
  prefix: string,
  count: number,
): Promise<void> {
  const value = Array.from({ length: count }, (_, index) => `${prefix}-${index}`).join("\n");
  const injected = await page.evaluate(
    ({ id, text }) => {
      const testWindow = window as typeof window & {
        __refmdSetEditorValueForDocument?: (documentId: string, value: string) => boolean;
      };
      return testWindow.__refmdSetEditorValueForDocument?.(id, text) ?? false;
    },
    { id: documentId, text: value },
  );
  if (injected) {
    await expectEditorTextContains(page, `${prefix}-${count - 1}`, 30_000);
    return;
  }

  const editor = page.locator(".cm-content, .ProseMirror, [role='textbox']").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click({ force: true });
  await editor.evaluate((element) => {
    if (element instanceof HTMLElement) element.focus();
  });
  await page.keyboard.press("Control+End");

  for (let i = 0; i < count; i += 1) {
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(`${prefix}-${i}`);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
}

test("same-account devices survive simultaneous reload of the same document", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.multiDevice);

  const contextA = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  const contextB = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  await Promise.all([
    contextA.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
    contextB.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
  ]);

  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();
  const diagnostics: string[] = [];
  const requestCounts = {
    authMeRequests: 0,
    authMe: 0,
    authMe401: 0,
    popChallengeRequests: 0,
    popChallenge: 0,
    popChallengeUnauthorized: 0,
    wsTokenRequests: 0,
    wsToken: 0,
    wsTokenUnauthorized: 0,
    transportFailures: 0,
    rateLimited: 0,
  };
  let countRequests = false;
  for (const [label, page] of [
    ["A", pageA],
    ["B", pageB],
  ] as const) {
    page.on("console", (message) => {
      const text = message.text();
      if (message.type() === "error" || text.includes("[ws]") || text.includes("[auto-sync]")) {
        diagnostics.push(`${label}: ${text}`);
      }
    });
    page.on("response", (response) => {
      if (!countRequests) return;
      const url = response.url();
      if (response.status() === 429) requestCounts.rateLimited += 1;
      if (url.includes("/api/auth/me")) {
        requestCounts.authMe += 1;
        if (response.status() === 401) requestCounts.authMe401 += 1;
      }
      if (url.includes("/api/auth/rrp-challenge")) {
        requestCounts.popChallenge += 1;
        if (response.status() === 401 || response.status() === 403) {
          requestCounts.popChallengeUnauthorized += 1;
          diagnostics.push(`${label}: rrp-challenge ${response.status()}`);
        }
      }
      if (url.includes("/api/auth/ws-token")) {
        requestCounts.wsToken += 1;
        if (response.status() === 401 || response.status() === 403) {
          requestCounts.wsTokenUnauthorized += 1;
          diagnostics.push(`${label}: ws-token ${response.status()}`);
        }
      }
    });
    page.on("request", (request) => {
      if (!countRequests) return;
      const url = request.url();
      if (url.includes("/api/auth/me")) requestCounts.authMeRequests += 1;
      if (url.includes("/api/auth/rrp-challenge")) requestCounts.popChallengeRequests += 1;
      if (url.includes("/api/auth/ws-token")) requestCounts.wsTokenRequests += 1;
    });
    page.on("requestfailed", (request) => {
      if (!countRequests) return;
      const url = request.url();
      if (url.includes("/api/auth/rrp-challenge") || url.includes("/api/auth/ws-token")) {
        const failureText = request.failure()?.errorText ?? "unknown";
        diagnostics.push(`${label}: ${url} failed: ${failureText}`);
        if (failureText.includes("ERR_ABORTED") || failureText.includes("NS_BINDING_ABORTED")) {
          return;
        }
        requestCounts.transportFailures += 1;
      }
    });
  }

  try {
    const email = await registerAccount(pageA);
    await createDocument(pageA, "Simultaneous Reload Doc");
    await openDocument(pageA, "Simultaneous Reload Doc");
    const documentId = pageA.url().match(/\/document\/([^/?#]+)/)?.[1];
    if (!documentId) throw new Error(`document id not found: ${pageA.url()}`);

    await loginForDeviceRegistration(pageB, email);
    await expect(pageA.getByRole("button", { name: /Emojis Match.*Approve/i })).toBeVisible({
      timeout: 120_000,
    });
    await pageA.getByRole("button", { name: /Emojis Match.*Approve/i }).click();
    await expect(pageB).toHaveURL(/dashboard/, { timeout: 120_000 });
    await waitForWorkspaceReady(pageB);

    await openDocument(pageA, "Simultaneous Reload Doc");
    await openDocument(pageB, "Simultaneous Reload Doc");
    await waitForSyncReady(pageA, documentId, "device A before reload");
    await waitForSyncReady(pageB, documentId, "device B before reload");

    await typeLineBurst(pageA, documentId, "snapshot-seed", 120);
    await expectEditorTextContains(pageB, "snapshot-seed-119", 120_000);
    await waitForSyncReady(pageA, documentId, "device A before snapshot reload");
    await waitForSyncReady(pageB, documentId, "device B before snapshot reload");

    countRequests = true;
    await Promise.all([
      pageA.reload({ waitUntil: "domcontentloaded" }),
      pageB.reload({ waitUntil: "domcontentloaded" }),
    ]);

    await expectEditorTextContains(pageA, "snapshot-seed-119", 90_000);
    await expectEditorTextContains(pageB, "snapshot-seed-119", 90_000);
    await waitForSyncReady(pageA, documentId, `device A after reload\n${diagnostics.join("\n")}`);
    await waitForSyncReady(pageB, documentId, `device B after reload\n${diagnostics.join("\n")}`);
    countRequests = false;

    expect(
      requestCounts.rateLimited,
      `429 after simultaneous reload\n${diagnostics.join("\n")}`,
    ).toBe(0);
    expect(
      requestCounts.authMe401,
      `auth/me 401 storm after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBe(0);
    expect(
      requestCounts.authMeRequests,
      `auth/me storm after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBeLessThanOrEqual(6);
    expect(
      requestCounts.wsTokenRequests,
      `ws-token storm after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBeLessThanOrEqual(8);
    expect(
      requestCounts.wsTokenUnauthorized,
      `ws-token unauthorized after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBe(0);
    expect(
      requestCounts.popChallengeRequests,
      `rrp-challenge requests were not bounded after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBeLessThanOrEqual(60);
    expect(
      requestCounts.popChallengeUnauthorized,
      `rrp-challenge unauthorized after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBe(0);
    expect(
      requestCounts.transportFailures,
      `auth transport failures after simultaneous reload: ${JSON.stringify(requestCounts)}\n${diagnostics.join("\n")}`,
    ).toBe(0);
  } finally {
    await contextA.close();
    await contextB.close();
  }
});
