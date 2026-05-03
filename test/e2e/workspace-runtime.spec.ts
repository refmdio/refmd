import { test, expect, type Page } from "@playwright/test";
import {
  createDocument,
  createWorkspace,
  openDocument,
  registerAccount,
  switchWorkspace,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;
let defaultWorkspaceName: string;

async function openPanelMenu(page: Page, panelSelector: string) {
  const panel = page.locator(panelSelector).first();
  const windowRoot = panel.locator(
    'xpath=ancestor::*[contains(@class,"mosaic-window-body")]/parent::*[contains(@class,"mosaic-window")]',
  );
  await panel.click();
  await windowRoot.locator('[data-slot="dropdown-menu-trigger"]').click();
}

async function panelCount(page: Page): Promise<number> {
  return page.locator("[data-panel-id]").count();
}

async function customLeafCount(page: Page): Promise<number> {
  return page.locator('[data-panel-id^="leaf-"]').count();
}

async function openCommandPalette(page: Page): Promise<void> {
  await page.keyboard.press("Control+P");
  await expect(page.locator('input[placeholder="Type a command..."]')).toBeVisible({
    timeout: 10_000,
  });
}

async function runCommand(page: Page, query: string, commandName: string): Promise<void> {
  await openCommandPalette(page);
  const input = page.locator('input[placeholder="Type a command..."]');
  await input.fill(query);
  const option = page.getByRole("option", { name: commandName });
  if (await option.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await option.click();
    return;
  }
  await page.getByRole("button", { name: commandName }).click();
}

async function revealDocumentTreeLeaf(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const app = (globalThis as { __REFMD_APP_INSTANCE__?: unknown }).__REFMD_APP_INSTANCE__ as {
      workspace: {
        getLeaf(newLeaf?: boolean | "split"): {
          setViewState(state: { type: string; state?: Record<string, unknown> }): Promise<void>;
        };
        revealLeaf(leaf: unknown): void;
      };
    };
    const leaf = app.workspace.getLeaf(true);
    await leaf.setViewState({ type: "document-tree" });
    app.workspace.revealLeaf(leaf);
  });
}

test.describe.serial("Workspace Runtime", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account and create workspace documents", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    defaultWorkspaceName =
      (await sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]').textContent())?.trim() ??
      "";
    await createDocument(sharedPage, "Runtime Doc A");
    await openDocument(sharedPage, "Runtime Doc A");
  });

  test("document panel menu split and close still work after tile refactor", async () => {
    test.setTimeout(60_000);

    const initialPanelCount = await panelCount(sharedPage);
    await openPanelMenu(sharedPage, '[data-panel-id*=":"]');
    await sharedPage.getByRole("menuitem", { name: "Split Horizontal" }).click();

    await expect
      .poll(() => panelCount(sharedPage), {
        timeout: 10_000,
        message: "panel split did not create a second tile",
      })
      .toBeGreaterThan(initialPanelCount);

    const panelIds = await sharedPage.locator("[data-panel-id]").evaluateAll((els) =>
      els
        .map((el) => el.getAttribute("data-panel-id") ?? "")
        .filter((id) => id.length > 0),
    );
    const targetPanelId = panelIds[0];
    await openPanelMenu(sharedPage, `[data-panel-id="${targetPanelId}"]`);
    await sharedPage.getByRole("menuitem", { name: "Close" }).click();

    await expect
      .poll(() => panelCount(sharedPage), {
        timeout: 10_000,
        message: "close panel menu action did not remove a tile",
      })
      .toBe(initialPanelCount);
  });

  test("custom leaf can still mount into the workspace mosaic", async () => {
    test.setTimeout(60_000);

    await revealDocumentTreeLeaf(sharedPage);

    await expect
      .poll(() => customLeafCount(sharedPage), {
        timeout: 10_000,
        message: "custom leaf was not mounted into the workspace",
      })
      .toBeGreaterThan(0);

    const customLeaf = sharedPage.locator('[data-panel-id^="leaf-"]').first();
    await expect(customLeaf.locator('[title="New Document"]')).toBeVisible({ timeout: 10_000 });
  });

  test("workspace switch keeps plugins and runtime wiring alive", async () => {
    test.setTimeout(120_000);

    await openDocument(sharedPage, "Runtime Doc A");
    await sharedPage.locator('[data-panel-id*=":"]').first().click();

    await createWorkspace(sharedPage, "Runtime Workspace 2");
    await createDocument(sharedPage, "Runtime Doc B");
    await openDocument(sharedPage, "Runtime Doc B");
    await expect(sharedPage.locator("aside").getByText("Runtime Doc B")).toBeVisible({
      timeout: 10_000,
    });
    await expect(sharedPage.locator("aside").getByText("Runtime Doc A")).not.toBeVisible({
      timeout: 5_000,
    });

    await switchWorkspace(sharedPage, defaultWorkspaceName);
    await expect(sharedPage.locator("aside").getByText("Runtime Doc A")).toBeVisible({
      timeout: 10_000,
    });
    await expect(sharedPage.locator("aside").getByText("Runtime Doc B")).not.toBeVisible({
      timeout: 5_000,
    });
    await openDocument(sharedPage, "Runtime Doc A");
    await sharedPage.locator('[data-panel-id*=":"]').first().click();
    const panelCountBefore = await panelCount(sharedPage);

    await runCommand(sharedPage, "split editor vertically", "Split editor vertically");

    await expect
      .poll(() => panelCount(sharedPage), {
        timeout: 10_000,
        message: "command palette command did not execute after workspace switch",
      })
      .toBeGreaterThan(panelCountBefore);
  });
});
