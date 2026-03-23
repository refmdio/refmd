import { test, expect, type Page } from "@playwright/test";
import { registerAccount, createDocument, openDocument } from "./helpers";

let sharedPage: Page;

test.describe.serial("Editor Modes", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register, create, open document", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Mode Test Doc");
    await openDocument(sharedPage, "Mode Test Doc");
  });

  // MODE-01
  test("default editor is Markdown with CodeMirror visible", async () => {
    test.setTimeout(10_000);
    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 5_000 });
  });

  // MODE-02
  test("type content in Markdown mode", async () => {
    test.setTimeout(30_000);
    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.type("Hello from Markdown");
    await sharedPage.waitForTimeout(2000);
  });

  // MODE-03
  test("switch to WYSIWYG mode via panel menu", async () => {
    test.setTimeout(30_000);

    // Open dropdown menu trigger in the editor panel (not sidebar)
    // The panel menu trigger is outside aside (in the editor workspace area)
    const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
    await trigger.waitFor({ state: "visible", timeout: 10_000 });
    await trigger.click();

    // Wait for dropdown content to appear
    const content = sharedPage.locator('[data-slot="dropdown-menu-content"]');
    await content.waitFor({ state: "visible", timeout: 5_000 });

    await content.locator('[data-slot="dropdown-menu-item"]', { hasText: "WYSIWYG" }).click();
    await sharedPage.waitForTimeout(2000);

    await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
    await expect(sharedPage.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
  });

  // MODE-04
  test("content preserved after switching to WYSIWYG", async () => {
    test.setTimeout(10_000);
    const text = await sharedPage.locator(".ProseMirror").textContent();
    expect(text).toContain("Hello from Markdown");
  });

  // MODE-05
  test("switch to Split mode", async () => {
    test.setTimeout(30_000);

    // The panel menu trigger is outside aside (in the editor workspace area)
    const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
    await trigger.waitFor({ state: "visible", timeout: 10_000 });
    await trigger.click();
    await sharedPage.waitForTimeout(500);

    const splitContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
    await splitContent.waitFor({ state: "visible", timeout: 5_000 });
    await splitContent.getByRole("menuitem", { name: "Switch to Split" }).click();
    await sharedPage.waitForTimeout(2000);

    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
    await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
  });

  // MODE-06
  test("collapse to Markdown only from Split", async () => {
    test.setTimeout(30_000);

    // The panel menu trigger is outside aside (in the editor workspace area)
    const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
    await trigger.waitFor({ state: "visible", timeout: 10_000 });
    await trigger.click();
    await sharedPage.waitForTimeout(500);

    const mdContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
    await mdContent.waitFor({ state: "visible", timeout: 5_000 });
    await mdContent.locator('[data-slot="dropdown-menu-item"]', { hasText: "Markdown only" }).click();
    await sharedPage.waitForTimeout(2000);

    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
    await expect(sharedPage.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
  });

  // MODE-07
  test("content preserved through all mode switches", async () => {
    test.setTimeout(10_000);
    const text = await sharedPage.locator(".cm-content").textContent();
    expect(text).toContain("Hello from Markdown");
  });
});
