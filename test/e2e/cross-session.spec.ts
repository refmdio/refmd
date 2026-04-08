import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  login,
  logout,
  createDocument,
  openDocument,
  collectErrors,
  expectEditorTextContains,
} from "./helpers";

let sharedPage: Page;
let email: string;

test.describe.serial("Cross-Session Persistence", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // XSESS-01
  test("setup: register, create document, type content", async () => {
    test.setTimeout(180_000);
    email = await registerAccount(sharedPage);
    await createDocument(sharedPage, "Persist Doc");
    await openDocument(sharedPage, "Persist Doc");

    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.type("Cross-session content");
    await sharedPage.waitForTimeout(10000);
  });

  // XSESS-02
  test("logout", async () => {
    test.setTimeout(30_000);
    await logout(sharedPage);
  });

  // XSESS-03
  test("login with same credentials reaches dashboard", async () => {
    test.setTimeout(180_000);
    await login(sharedPage, email);
    await expect(sharedPage.getByRole("button", { name: "New Document" })).toBeVisible({
      timeout: 30_000,
    });
  });

  // XSESS-04
  test("document appears in sidebar after re-login", async () => {
    test.setTimeout(30_000);
    await expect(
      sharedPage.locator("aside").getByText("Persist Doc"),
    ).toBeVisible({ timeout: 15_000 });
  });

  // XSESS-05
  test("document content matches pre-logout content", async () => {
    test.setTimeout(30_000);
    await openDocument(sharedPage, "Persist Doc");

    await expectEditorTextContains(sharedPage, "Cross-session content", 10_000);
  });

  // XSESS-06
  test("editing after re-login works without errors", async () => {
    test.setTimeout(60_000);

    const errors = await collectErrors(sharedPage, async () => {
      const editor = sharedPage.locator(".cm-content, .ProseMirror").first();
      await editor.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.keyboard.press("Enter");
      await sharedPage.keyboard.type("Post-login edit");
      await sharedPage.waitForTimeout(10000);
    });

    const syncErrors = errors.filter(
      (e) => e.includes("verification_failed") || e.includes("snapshot recovery failed"),
    );
    expect(syncErrors).toHaveLength(0);
  });
});
