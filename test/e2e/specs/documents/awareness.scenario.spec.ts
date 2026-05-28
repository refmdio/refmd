import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

function panelMenuTrigger() {
  return sharedPage.locator(
    ".mosaic-window-toolbar [data-slot='dropdown-menu-trigger'], .mosaic-window-toolbar button",
  ).last();
}

test.describe.serial("Awareness & Ephemeral Session (4-23)", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // AWARE-01: Setup and verify no errors during initial document open with awareness
  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.extendedScenario);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Awareness Test Doc");

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, "Awareness Test Doc");
      // Wait for full init: DEK + channel join + ephemeral session + awareness relay
      await sharedPage.waitForTimeout(E2E_DELAYS.awarenessSettle);
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

  test("awareness remains error-free while editing and syncing split panels", async () => {
    test.setTimeout(E2E_TIMEOUTS.syncScenario);

    await test.step("typing with awareness active produces no errors", async () => {
      const errors = await collectErrors(sharedPage, async () => {
        const editor = sharedPage.locator(".cm-content");
        await editor.click();

        for (let i = 0; i < 10; i++) {
          await sharedPage.keyboard.insertText(`Awareness test line ${i}. `);
          await sharedPage.keyboard.press("Enter");
          await sharedPage.waitForTimeout(E2E_DELAYS.tinyPoll);
        }

        await sharedPage.waitForTimeout(E2E_DELAYS.syncSettle);
      });

      const syncErrors = errors.filter(
        (e) =>
          e.includes("verification_failed") ||
          e.includes("snapshot recovery failed") ||
          e.includes("Ephemeral processing error"),
      );
      expect(syncErrors).toHaveLength(0);
    });

    await test.step("split mode with awareness active produces no errors", async () => {
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
        const trigger = panelMenuTrigger();
        await trigger.waitFor({ state: "visible", timeout: 10_000 });
        await trigger.click();
        await sharedPage.waitForTimeout(E2E_DELAYS.poll);

        const menuContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
        await menuContent.waitFor({ state: "visible", timeout: 5_000 });
        await menuContent
          .locator('[data-slot="dropdown-menu-item"]', { hasText: "Switch to Split" })
          .click();
        await sharedPage.waitForTimeout(E2E_DELAYS.routeSettle);
      }

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });

      const errors = await collectErrors(sharedPage, async () => {
        await sharedPage.locator(".cm-content").click();
        await sharedPage.keyboard.insertText("Split CM edit. ");
        await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

        await sharedPage.locator(".ProseMirror").click();
        await sharedPage.keyboard.insertText("Split PM edit. ");
        await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);
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

    await test.step("content syncs between CM and PM in split view", async () => {
      const cmTexts = await sharedPage.locator(".cm-content").allTextContents();
      const pmTexts = await sharedPage.locator(".ProseMirror").allTextContents();
      const allCmText = cmTexts.join(" ");
      const allPmText = pmTexts.join(" ");

      expect(allCmText).toContain("Split PM edit.");
      expect(allPmText).toContain("Split PM edit.");
    });
  });
});
