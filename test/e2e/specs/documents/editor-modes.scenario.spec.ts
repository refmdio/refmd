import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

test.describe.serial("Editor Modes", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Mode Test Doc");
    await openDocument(sharedPage, "Mode Test Doc");
  });

  test("editor content survives Markdown, WYSIWYG, and Split mode transitions", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    await test.step("default editor is Markdown with CodeMirror visible", async () => {
      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 5_000 });
    });

    await test.step("type content in Markdown mode", async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();
      await sharedPage.keyboard.insertText("Hello from Markdown");
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);
    });

    await test.step("switch to WYSIWYG mode via panel menu", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();

      const content = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await content.waitFor({ state: "visible", timeout: 5_000 });

      await content.locator('[data-slot="dropdown-menu-item"]', { hasText: "WYSIWYG" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });

    await test.step("switch to Split mode", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const splitContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await splitContent.waitFor({ state: "visible", timeout: 5_000 });
      await splitContent.getByRole("menuitem", { name: "Switch to Split" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
    });

    await test.step("collapse to Markdown only from Split", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const mdContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await mdContent.waitFor({ state: "visible", timeout: 5_000 });
      await mdContent.locator('[data-slot="dropdown-menu-item"]', { hasText: "Markdown only" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
    });

    await test.step("content preserved through all mode switches", async () => {
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await openDocument(sharedPage, "Mode Test Doc");
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });
  });
});
