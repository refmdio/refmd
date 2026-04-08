/**
 * Single-User Multi-Device Sync Test
 *
 * Same account, two browser contexts (= two devices).
 * Verifies that edits on device A appear on device B and vice versa.
 */

import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import {
  TEST_PASSWORD,
  createDocument,
  expectEditorTextContains,
  openDocument,
  registerAccount,
  waitForWorkspaceReady,
} from "./helpers";

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  const codeMirror = page.locator(".cm-content").first();
  if (await codeMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await codeMirror.click();
    await page.keyboard.press("End");
    await page.keyboard.press("Enter");
    await page.keyboard.type(text);
    return;
  }

  const proseMirror = page.locator(".ProseMirror").first();
  await expect(proseMirror).toBeVisible({ timeout: 15_000 });
  await proseMirror.click();
  await page.keyboard.press("End");
  await page.keyboard.press("Enter");
  await page.keyboard.type(text);
}

async function focusVisibleEditor(page: Page): Promise<void> {
  const panel = page.locator("[data-panel-id]").first();
  if (await panel.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await panel.click({ position: { x: 8, y: 8 } });
  }

  const codeMirror = page.locator(".cm-content").first();
  if (await codeMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await codeMirror.click();
    return;
  }

  const proseMirror = page.locator(".ProseMirror").first();
  await expect(proseMirror).toBeVisible({ timeout: 15_000 });
  await proseMirror.click();
}

async function ensureEditorReady(page: Page, title: string): Promise<void> {
  const hasEditor = await page
    .locator(".cm-content, .ProseMirror")
    .first()
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  if (hasEditor) return;

  const hasDisconnectedPanels = await page
    .getByText("disconnected", { exact: true })
    .first()
    .isVisible({ timeout: 1_000 })
    .catch(() => false);
  if (hasDisconnectedPanels) {
    await page.goto("/dashboard");
    await waitForWorkspaceReady(page);
  }
  await openDocument(page, title);
}

async function loginForDeviceRegistration(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });
}

let ctxA: BrowserContext;
let ctxB: BrowserContext;
let pageA: Page;
let pageB: Page;
let email: string;

test.describe.serial("Single-User Multi-Device Sync", () => {
  test.beforeAll(async ({ browser }) => {
    ctxA = await browser.newContext({ bypassCSP: true, acceptDownloads: true });
    ctxB = await browser.newContext({ bypassCSP: true, acceptDownloads: true });
    pageA = await ctxA.newPage();
    pageB = await ctxB.newPage();
  });

  test.afterAll(async () => {
    await ctxA.close();
    await ctxB.close();
  });

  test("register on device A, create document, type content", async () => {
    test.setTimeout(360_000);
    email = await registerAccount(pageA);
    await createDocument(pageA, "Multi Device Doc");
    await openDocument(pageA, "Multi Device Doc");
    await pageA.waitForTimeout(5000);

    await pageA.locator(".cm-content").click();
    await pageA.keyboard.type("From device A. ");
    await pageA.waitForTimeout(5000);
  });

  test("login on device B and approve from device A", async () => {
    test.setTimeout(360_000);

    // Device B: login → redirects to /devices/register
    await loginForDeviceRegistration(pageB, email);

    // Device A: wait for pending device notification dialog
    await expect(
      pageA.getByRole("button", { name: /Emojis Match.*Approve/i }),
    ).toBeVisible({ timeout: 120_000 });

    // Click approve
    await pageA.getByRole("button", { name: /Emojis Match.*Approve/i }).click();

    // Device B: should be redirected to dashboard after approval
    await expect(pageB).toHaveURL(/dashboard/, { timeout: 120_000 });
    await waitForWorkspaceReady(pageB);
    await pageB.waitForTimeout(5000);

    // Open the document on device B
    await expect(pageB.locator("aside").getByText("Multi Device Doc")).toBeVisible({
      timeout: 30_000,
    });
    await openDocument(pageB, "Multi Device Doc");
  });

  test("device B types, device A sees it", async () => {
    test.setTimeout(90_000);

    await ensureEditorReady(pageB, "Multi Device Doc");
    await typeInVisibleEditor(pageB, "From device B. ");
    await expectEditorTextContains(pageA, "From device B.", 60_000);
  });

  test("same-user other-device session remains interactive", async () => {
    test.setTimeout(30_000);

    await ensureEditorReady(pageA, "Multi Device Doc");
    await ensureEditorReady(pageB, "Multi Device Doc");
    await expectEditorTextContains(pageA, "From device B.", 15_000);
    await expectEditorTextContains(pageB, "From device B.", 15_000);
  });
});
