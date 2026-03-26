/**
 * Single-User Multi-Device Sync Test
 *
 * Same account, two browser contexts (= two devices).
 * Verifies that edits on device A appear on device B and vice versa.
 */

import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import { TEST_PASSWORD, testEmail } from "./helpers";

async function register(page: Page): Promise<string> {
  const email = testEmail();
  await page.goto("/auth/register", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(3000);
  await page.locator("#name").waitFor({ state: "visible", timeout: 60_000 });
  await page.locator("#name").fill("E2E User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({ timeout: 120_000 });
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(1000);
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });
  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  return email;
}

async function login(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(3000);
  await page.locator("#email").waitFor({ state: "visible", timeout: 60_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  // May redirect to /dashboard (existing device) or /devices/register (new device)
  await expect(page).toHaveURL(/dashboard|devices\/register/, { timeout: 120_000 });
}

async function createDocument(page: Page, title: string): Promise<void> {
  await page.waitForTimeout(2000);
  await page.locator("aside button").first().click();
  await page.waitForTimeout(2000);
  await page.locator('input[placeholder="Document title"]').fill(title);
  await page.getByText("Create", { exact: true }).click();
  await expect(page.locator("aside").getByText(title)).toBeVisible({ timeout: 10_000 });
}

async function openDocument(page: Page, title: string): Promise<void> {
  await page.locator("aside").getByText(title).click();
  await expect(page.locator(".cm-content")).toBeVisible({ timeout: 15_000 });
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
    test.setTimeout(180_000);
    email = await register(pageA);
    await createDocument(pageA, "Multi Device Doc");
    await openDocument(pageA, "Multi Device Doc");
    await pageA.waitForTimeout(5000);

    await pageA.locator(".cm-content").click();
    await pageA.keyboard.type("From device A. ");
    await pageA.waitForTimeout(5000);
  });

  test("login on device B and approve from device A", async () => {
    test.setTimeout(300_000);

    // Device B: login → redirects to /devices/register
    await login(pageB, email);

    // Device B is now on /devices/register, waiting for approval
    await expect(pageB).toHaveURL(/devices\/register/, { timeout: 30_000 });

    // Device A: wait for pending device notification dialog
    await expect(
      pageA.getByRole("button", { name: /Emojis Match.*Approve/i }),
    ).toBeVisible({ timeout: 120_000 });

    // Click approve
    await pageA.getByRole("button", { name: /Emojis Match.*Approve/i }).click();

    // Device B: should be redirected to dashboard after approval
    await expect(pageB).toHaveURL(/dashboard/, { timeout: 120_000 });
    await pageB.waitForTimeout(5000);

    // Open the document on device B
    await expect(pageB.locator("aside").getByText("Multi Device Doc")).toBeVisible({
      timeout: 30_000,
    });
    await openDocument(pageB, "Multi Device Doc");
    await pageB.waitForTimeout(10000);

    const text = await pageB.locator(".cm-content").innerText();
    expect(text).toContain("From device A.");
  });

  test("device B types, device A sees it", async () => {
    test.setTimeout(60_000);

    // CDP to verify WS activity
    const cdpB = await pageB.context().newCDPSession(pageB);
    await cdpB.send("Network.enable");
    const framesB: string[] = [];
    cdpB.on("Network.webSocketFrameSent", (p) => {
      if (p.response.payloadData.includes('"update"'))
        framesB.push("SENT update");
    });
    cdpB.on("Network.webSocketFrameReceived", (p) => {
      if (p.response.payloadData.includes('"update-saved"'))
        framesB.push("RECV update-saved");
    });

    const cdpA = await pageA.context().newCDPSession(pageA);
    await cdpA.send("Network.enable");
    const framesA: string[] = [];
    cdpA.on("Network.webSocketFrameReceived", (p) => {
      if (p.response.payloadData.includes('"update"'))
        framesA.push("RECV update");
    });

    await pageB.locator(".cm-content").click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.type("From device B. ");
    await pageB.waitForTimeout(10000);

    console.log(`[diag] Device B: ${framesB.join(", ")}`);
    console.log(`[diag] Device A: ${framesA.join(", ")}`);

    await cdpB.detach();
    await cdpA.detach();

    // Device A should see device B's content
    await pageA.locator(".cm-content").click();
    await pageA.keyboard.press("Control+End");
    await pageA.waitForTimeout(1000);
    const textA = await pageA.locator(".cm-content").innerText();
    expect(textA).toContain("From device B.");
  });

  test("same-user other-device avatar shown with faded style", async () => {
    test.setTimeout(30_000);

    // Device A should see an avatar for device B (same user, other device)
    // The avatar is wrapped in a div.relative with title attribute
    const avatarWrappers = pageA.locator(".mosaic-window-toolbar .relative");
    await expect(avatarWrappers.first()).toBeVisible({ timeout: 15_000 });

    // Verify it has the "other device" title on the wrapper
    const title = await avatarWrappers.first().getAttribute("title");
    expect(title).toContain("other device");

    // Verify the same-user indicator dot is visible
    const dot = avatarWrappers.first().locator("span");
    await expect(dot).toBeVisible({ timeout: 5_000 });
  });

  test("device A types more, device B sees it", async () => {
    test.setTimeout(60_000);

    await pageA.locator(".cm-content").click();
    await pageA.keyboard.press("End");
    await pageA.keyboard.press("Enter");
    await pageA.keyboard.type("More from A. ");
    await pageA.waitForTimeout(10000);

    await pageB.locator(".cm-content").click();
    await pageB.keyboard.press("Control+End");
    await pageB.waitForTimeout(1000);
    const textB = await pageB.locator(".cm-content").innerText();
    expect(textB).toContain("More from A.");
  });
});
