/**
 * Multi-User Awareness E2E Tests (4-23)
 *
 * Tests cursor sync and presence avatars across two users collaborating
 * on the same document in the same workspace.
 *
 * Flow:
 *   1. User A registers, creates a workspace document
 *   2. User A invites User B via workspace settings
 *   3. User B registers in a separate browser context
 *   4. User B accepts the invitation
 *   5. Both users open the same document
 *   6. Verify presence avatars and content sync
 */

import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import { TEST_PASSWORD, testEmail, collectErrors } from "./helpers";

// ── Helpers ──────────────────────────────────────────────

async function registerAccount(page: Page): Promise<string> {
  const email = testEmail();
  await page.goto("/auth/register");
  await page.waitForTimeout(2000);
  await page.locator("#name").fill("E2E User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(1000);
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });
  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  return email;
}

async function registerWithName(page: Page, name: string): Promise<string> {
  const email = testEmail();
  await page.goto("/auth/register", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(3000);
  await page.locator("#name").waitFor({ state: "visible", timeout: 60_000 });
  await page.locator("#name").fill(name);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(1000);
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });
  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  return email;
}

async function login(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await page.waitForTimeout(2000);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/dashboard/, { timeout: 120_000 });
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

async function openSettings(page: Page): Promise<void> {
  await page.locator('button[aria-label="Settings"]').click();
  await page.waitForTimeout(1000);
}

async function selectSettingsTab(page: Page, tabName: string): Promise<void> {
  await page.getByRole("tab", { name: tabName }).click();
  await page.waitForTimeout(500);
}

/**
 * Invite a user via the workspace settings UI.
 * Returns the invitation link.
 */
async function inviteUser(page: Page, email: string): Promise<string> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");
  await page.waitForTimeout(2000);

  // Click "Invite" button
  await page.getByRole("button", { name: "Invite" }).click();
  await page.waitForTimeout(1000);

  // Fill email in the invite dialog
  await page.locator("#invite-email").fill(email);
  await page.waitForTimeout(500);

  // Click "Create Invitation"
  await page.getByRole("button", { name: "Create Invitation" }).click();

  // Wait for the invitation link to appear
  await expect(page.getByText("Invitation created")).toBeVisible({ timeout: 30_000 });

  // Extract the invitation link from the readonly input
  const linkInput = page.locator('[role="dialog"] input[readonly]');
  const link = await linkInput.inputValue();

  // Close dialog
  await page.getByRole("button", { name: "Done" }).click();
  await page.waitForTimeout(500);

  // Close settings
  await page.keyboard.press("Escape");
  await page.waitForTimeout(500);

  return link;
}

/**
 * Accept an invitation link. Page must be authenticated.
 */
async function acceptInvitation(page: Page, link: string): Promise<void> {
  await page.goto(link);
  await page.waitForTimeout(3000);

  // Wait for "Accept Invitation" button (confirm state)
  await expect(page.getByRole("button", { name: "Accept Invitation" })).toBeVisible({
    timeout: 60_000,
  });
  await page.getByRole("button", { name: "Accept Invitation" }).click();

  // Wait for success (auto-redirects to dashboard after 2s)
  await expect(page).toHaveURL(/dashboard/, { timeout: 60_000 });
  await page.waitForTimeout(3000);
}

// ── Tests ────────────────────────────────────────────────

let ctxA: BrowserContext;
let ctxB: BrowserContext;
let pageA: Page;
let pageB: Page;
let emailA: string;
let emailB: string;
let cdpSessionB: any;
const wsFramesBuf: string[] = [];

test.describe.serial("Multi-User Awareness & Presence (4-23)", () => {
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

  // MULTI-01a: Register User A
  test("register User A", async () => {
    test.setTimeout(180_000);
    emailA = await registerWithName(pageA, "Alice");
  });

  // MULTI-01b: Register User B
  test("register User B", async () => {
    test.setTimeout(180_000);
    emailB = await registerWithName(pageB, "Bob");
  });

  // MULTI-02: User A creates a document
  test("User A creates a document", async () => {
    test.setTimeout(60_000);

    await createDocument(pageA, "Collab Doc");
    await openDocument(pageA, "Collab Doc");
    await pageA.waitForTimeout(5000);

    // Type some content
    const editor = pageA.locator(".cm-content");
    await editor.click();
    await pageA.keyboard.type("Hello from Alice. ");
    await pageA.waitForTimeout(3000);
  });

  // MULTI-03: User A invites User B
  test("User A invites User B to workspace", async () => {
    test.setTimeout(60_000);

    const inviteLink = await inviteUser(pageA, emailB);
    expect(inviteLink).toContain("/invite#token=");

    // Store the link for User B
    (test.info() as any).__inviteLink = inviteLink;

    // Workaround: save to a shared variable since test.info() doesn't persist
    await pageA.evaluate(
      (link) => {
        (window as any).__inviteLink = link;
      },
      inviteLink,
    );
  });

  // MULTI-04: User B accepts invitation
  test("User B accepts invitation", async () => {
    test.setTimeout(120_000);

    // Retrieve the invite link from User A's page context
    const inviteLink = await pageA.evaluate(() => (window as any).__inviteLink);
    expect(inviteLink).toBeTruthy();

    await acceptInvitation(pageB, inviteLink as string);
  });

  // MULTI-05: User B switches to the shared workspace and opens the document
  test("User B opens the shared document", async () => {
    test.setTimeout(60_000);

    // Start CDP BEFORE opening doc to capture channel join + all WS frames
    cdpSessionB = await pageB.context().newCDPSession(pageB);
    await cdpSessionB.send("Network.enable");
    cdpSessionB.on("Network.webSocketFrameSent", (params) => {
      wsFramesBuf.push(`SENT: ${params.response.payloadData.substring(0, 300)}`);
    });
    cdpSessionB.on("Network.webSocketFrameReceived", (params) => {
      wsFramesBuf.push(`RECV: ${params.response.payloadData.substring(0, 300)}`);
    });

    await expect(pageB.locator("aside").getByText("Collab Doc")).toBeVisible({
      timeout: 30_000,
    });

    await openDocument(pageB, "Collab Doc");
    await pageB.waitForTimeout(10000);

    // Dump all WS frames captured during doc open
    console.log(`[debug] User B WS frames during doc open (${wsFramesBuf.length}):`);
    for (const f of wsFramesBuf) console.log(`  ${f}`);

    const text = await pageB.locator(".cm-content").innerText();
    expect(text).toContain("Hello from Alice.");
  });

  // MULTI-06: Both users have awareness active — User B types
  test("User B types and both users see synced content", async () => {
    test.setTimeout(120_000);

    // Reset frame buffer for typing phase
    const wsFramesB = [...wsFramesBuf];
    wsFramesBuf.length = 0;

    // Also capture WS frames from User A for update broadcasts
    const cdpA = await pageA.context().newCDPSession(pageA);
    await cdpA.send("Network.enable");
    const wsFramesA: string[] = [];
    cdpA.on("Network.webSocketFrameReceived", (params) => {
      const data = params.response.payloadData;
      if (data.includes('"update"') || data.includes('"ephemeral"')) {
        wsFramesA.push(`RECV: ${data.substring(0, 300)}`);
      }
    });

    const editor = pageB.locator(".cm-content");
    await editor.click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.type("Hello from Bob. ");
    await pageB.waitForTimeout(5000);

    // Wait for sync to propagate to User A
    await pageA.waitForTimeout(15000);

    // Debug: dump WS frames from typing phase
    const typingFrames = wsFramesBuf;
    console.log(`[debug] User B WS frames during typing (${typingFrames.length}):`);
    for (const f of typingFrames.slice(0, 20)) console.log(`  ${f}`);
    console.log(`[debug] User A WS frames (${wsFramesA.length}):`);
    for (const f of wsFramesA.slice(0, 20)) console.log(`  ${f}`);

    await cdpA.detach();

    // Click at the end of the editor to scroll down
    const editorA = pageA.locator(".cm-content");
    await editorA.click();
    await pageA.keyboard.press("Control+End");
    await pageA.waitForTimeout(1000);

    const textA = await editorA.innerText();
    expect(textA).toContain("Hello from Bob.");
  });

  // MULTI-07: Presence avatars show remote user
  test("presence avatars show the other user", async () => {
    test.setTimeout(30_000);

    // User A should see Bob's avatar in the toolbar
    // The avatar is a colored circle with the first letter of the name
    const avatarsA = pageA.locator(".mosaic-window-toolbar .w-6.h-6.rounded-full");
    await expect(avatarsA.first()).toBeVisible({ timeout: 15_000 });

    // Verify the avatar shows "B" for Bob
    const avatarTextA = await avatarsA.first().textContent();
    expect(avatarTextA?.trim()).toBe("B");

    // User B should see Alice's avatar
    const avatarsB = pageB.locator(".mosaic-window-toolbar .w-6.h-6.rounded-full");
    await expect(avatarsB.first()).toBeVisible({ timeout: 15_000 });

    const avatarTextB = await avatarsB.first().textContent();
    expect(avatarTextB?.trim()).toBe("A");
  });

  // MULTI-07b: Remote cursor decorations are visible
  test("remote cursor decorations are visible in CodeMirror", async () => {
    test.setTimeout(30_000);

    // User A clicks into the editor to set a cursor position
    const editorA = pageA.locator(".cm-content");
    await editorA.click();
    await pageA.keyboard.press("Home");
    await pageA.waitForTimeout(3000);

    // User B's editor should show User A's remote cursor decoration
    // y-codemirror renders: .cm-ySelectionCaret (cursor line) and .cm-ySelectionInfo (name label)
    const remoteCursorB = pageB.locator(".cm-ySelectionCaret");
    await expect(remoteCursorB.first()).toBeVisible({ timeout: 15_000 });

    // User B clicks into the editor to set a cursor position
    const editorB = pageB.locator(".cm-content");
    await editorB.click();
    await pageB.keyboard.press("End");
    await pageB.waitForTimeout(3000);

    // User A's editor should show User B's remote cursor
    const remoteCursorA = pageA.locator(".cm-ySelectionCaret");
    await expect(remoteCursorA.first()).toBeVisible({ timeout: 15_000 });
  });

  // MULTI-08: User A types, User B sees update
  test("bidirectional content sync works", async () => {
    test.setTimeout(60_000);

    // User A types more
    const editorA = pageA.locator(".cm-content");
    await editorA.click();
    await pageA.keyboard.press("End");
    await pageA.keyboard.press("Enter");
    await pageA.keyboard.type("Alice adds more. ");
    await pageA.waitForTimeout(5000);

    // User B should see the new content
    const textB = await pageB.locator(".cm-content").innerText();
    expect(textB).toContain("Alice adds more.");
  });

  // MULTI-09: When User B leaves, User A's presence avatars eventually update
  test("presence avatar disappears when user leaves", async () => {
    test.setTimeout(30_000);

    // Close User B's page → server detects channel terminate → broadcasts peer-left
    await pageB.close();

    // peer-left should remove avatar within seconds (no 30s awareness timeout)
    const avatarsA = pageA.locator(".mosaic-window-toolbar .w-6.h-6.rounded-full");
    await expect(avatarsA).toHaveCount(0, { timeout: 10_000 });
  });
});
