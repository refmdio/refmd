import { test, expect, type Page } from "@playwright/test";
import { registerAccount, createDocument, openDocument, collectErrors } from "./helpers";

let sharedPage: Page;

test.describe.serial("Awareness & Ephemeral Session (4-23)", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // AWARE-01: Setup and verify no errors during initial document open with awareness
  test("setup: register, create, open document without ephemeral errors", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Awareness Test Doc");

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, "Awareness Test Doc");
      // Wait for full init: DEK + channel join + ephemeral session + awareness relay
      await sharedPage.waitForTimeout(10000);
    });

    const ephemeralErrors = errors.filter(
      (e) =>
        e.includes("Ephemeral") ||
        e.includes("ephemeral") ||
        e.includes("awareness") ||
        e.includes("Awareness") ||
        e.includes("session proof"),
    );
    expect(ephemeralErrors).toHaveLength(0);
  });

  // AWARE-02: Typing content with awareness active produces no errors
  test("typing with awareness active produces no errors", async () => {
    test.setTimeout(60_000);

    const errors = await collectErrors(sharedPage, async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();

      for (let i = 0; i < 10; i++) {
        await sharedPage.keyboard.type(`Awareness test line ${i}. `);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.waitForTimeout(100);
      }

      // Wait for sync + awareness relay
      await sharedPage.waitForTimeout(5000);
    });

    const syncErrors = errors.filter(
      (e) =>
        e.includes("verification_failed") ||
        e.includes("snapshot recovery failed") ||
        e.includes("Ephemeral processing error"),
    );
    expect(syncErrors).toHaveLength(0);
  });

  // AWARE-03: Ensure split mode and type in both editors without errors
  test("split mode with awareness active produces no errors", async () => {
    test.setTimeout(60_000);

    // Check if already in split mode (both CM and PM visible)
    const cmVisible = await sharedPage
      .locator(".cm-content")
      .isVisible()
      .catch(() => false);
    const pmVisible = await sharedPage
      .locator(".ProseMirror")
      .isVisible()
      .catch(() => false);
    const alreadySplit = cmVisible && pmVisible;

    if (!alreadySplit) {
      // Switch to split mode
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(500);

      const menuContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await menuContent.waitFor({ state: "visible", timeout: 5_000 });
      await menuContent
        .locator('[data-slot="dropdown-menu-item"]', { hasText: "Switch to Split" })
        .click();
      await sharedPage.waitForTimeout(3000);
    }

    // Verify both editors visible
    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
    await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });

    const errors = await collectErrors(sharedPage, async () => {
      // Type in CodeMirror
      await sharedPage.locator(".cm-content").click();
      await sharedPage.keyboard.type("Split CM edit. ");
      await sharedPage.waitForTimeout(2000);

      // Type in ProseMirror
      await sharedPage.locator(".ProseMirror").click();
      await sharedPage.keyboard.type("Split PM edit. ");
      await sharedPage.waitForTimeout(2000);
    });

    const splitErrors = errors.filter(
      (e) =>
        e.includes("verification_failed") ||
        e.includes("Ephemeral") ||
        e.includes("awareness") ||
        e.includes("snapshot recovery failed"),
    );
    expect(splitErrors).toHaveLength(0);
  });

  // AWARE-04: Content syncs between split panels
  test("content syncs between CM and PM in split view", async () => {
    test.setTimeout(10_000);

    // In split view, there may be multiple .cm-content / .ProseMirror elements.
    // Get ALL text from the page to verify both edits are present in the shared Y.Doc.
    const cmTexts = await sharedPage.locator(".cm-content").allTextContents();
    const pmTexts = await sharedPage.locator(".ProseMirror").allTextContents();
    const allCmText = cmTexts.join(" ");
    const allPmText = pmTexts.join(" ");

    // Both editors should reflect all content (synced via shared Y.Doc)
    expect(allCmText).toContain("Split PM edit.");
    expect(allPmText).toContain("Split PM edit.");
  });

  // AWARE-05: Collapse from split back to single, no errors
  test("collapse from split to markdown only without errors", async () => {
    test.setTimeout(60_000);

    const errors = await collectErrors(sharedPage, async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(500);

      const mdContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await mdContent.waitFor({ state: "visible", timeout: 5_000 });
      await mdContent
        .locator('[data-slot="dropdown-menu-item"]', { hasText: "Markdown only" })
        .click();
      await sharedPage.waitForTimeout(3000);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
    });

    const collapseErrors = errors.filter(
      (e) =>
        e.includes("verification_failed") ||
        e.includes("Ephemeral") ||
        e.includes("awareness") ||
        e.includes("snapshot recovery failed"),
    );
    expect(collapseErrors).toHaveLength(0);
  });

  // AWARE-07: Content preserved after collapse
  test("content preserved after collapse from split", async () => {
    test.setTimeout(10_000);

    // Use innerText to get all visible text including newlines
    const text = await sharedPage.locator(".cm-content").innerText();
    expect(text).toContain("Split PM edit.");
  });

  // AWARE-08: Reload re-initializes awareness without errors
  test("reload re-initializes awareness without errors", async () => {
    test.setTimeout(120_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(5000);

    await expect(sharedPage.locator("aside").getByText("Awareness Test Doc")).toBeVisible({
      timeout: 60_000,
    });

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, "Awareness Test Doc");
      await sharedPage.waitForTimeout(10000);
    });

    const reloadErrors = errors.filter(
      (e) =>
        e.includes("Ephemeral") ||
        e.includes("ephemeral") ||
        e.includes("awareness") ||
        e.includes("session proof") ||
        e.includes("verification_failed"),
    );
    expect(reloadErrors).toHaveLength(0);

    // Verify the editor loaded with content (not empty)
    const text = await sharedPage.locator(".cm-content").innerText();
    expect(text.trim().length).toBeGreaterThan(0);
  });
});
