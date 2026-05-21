import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import {
  blockApiRequests,
  expectEditorTextContains,
  indexedDbKeys,
  offlineKeyStoreKeys,
  openDocument,
  registerAccount,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;
let apiBlock: Awaited<ReturnType<typeof blockApiRequests>> | null = null;
const OFFLINE_CREATED_TEXT = "offline-created reconnect keeps this content";

async function installClientDiagnostics(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const normalize = (value: unknown): unknown => {
      if (value instanceof Error) {
        return {
          name: value.name,
          message: value.message,
          stack: value.stack,
          code: (value as Error & { code?: string }).code,
        };
      }
      if (Array.isArray(value)) return value.map(normalize);
      if (value && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
            key,
            normalize(nested),
          ]),
        );
      }
      return value;
    };
    const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
    w.__refmdE2EClientLogs = [];
    window.addEventListener("refmd:client-log", (event) => {
      const detail = (event as CustomEvent).detail;
      w.__refmdE2EClientLogs?.push(normalize(detail));
    });
  });
}

async function clientDiagnostics(page: Page): Promise<unknown[]> {
  return page
    .evaluate(() => {
      const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
      return (w.__refmdE2EClientLogs ?? []).slice(-10);
    })
    .catch(() => []);
}

async function offlineCreatedDiagnostics(page: Page): Promise<unknown> {
  return page
    .evaluate(async () => {
      return new Promise((resolve) => {
        const request = indexedDB.open("refmd-offline");
        request.onsuccess = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains("offline-created")) {
            db.close();
            resolve([]);
            return;
          }
          const tx = db.transaction("offline-created", "readonly");
          const getAll = tx.objectStore("offline-created").getAll();
          getAll.onsuccess = () => {
            db.close();
            resolve(
              getAll.result.map((entry: Record<string, unknown>) => ({
                documentId: entry.documentId,
                workspaceId: entry.workspaceId,
                syncBlockedReason: entry.syncBlockedReason,
                syncBlockedAt: entry.syncBlockedAt,
              })),
            );
          };
          getAll.onerror = () => {
            db.close();
            resolve([]);
          };
        };
        request.onerror = () => resolve([]);
      });
    })
    .catch(() => []);
}

async function focusMarkdownEditor(page: Page) {
  await page.bringToFront();
  const editor = page.locator(".cm-content").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await expect
    .poll(
      () =>
        page.evaluate(
          () => document.querySelector(".cm-content")?.getAttribute("contenteditable") ?? null,
        ),
      {
        timeout: 15_000,
        message: "CodeMirror editor did not become editable after offline document creation",
      },
    )
    .toBe("true");

  await editor.click({ position: { x: 12, y: 12 } });
  await page.getByRole("textbox").first().click({ position: { x: 12, y: 12 } });
  await editor.evaluate((element) => {
    if (!(element instanceof HTMLElement)) return;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(false);
    selection?.removeAllRanges();
    selection?.addRange(range);
    element.focus({ preventScroll: true });
  });
}

test.describe.serial("Offline-Created Document Sync", () => {
  test.beforeAll(async ({ browser }) => {
    const context = await newE2EContext(browser, { bypassCSP: true, serviceWorkers: "block" });
    await installClientDiagnostics(context);
    sharedPage = await context.newPage();
  });

  test.afterAll(async () => {
    await apiBlock?.unblock().catch(() => {});
    await sharedPage.context().close();
  });

  test("setup: register account, cache KEK, and go offline", async () => {
    test.setTimeout(180_000);

    await registerAccount(sharedPage);

    await sharedPage.locator("aside button").first().click();
    await sharedPage.locator('input[placeholder="Document title"]').fill("Offline Seed Doc");
    await sharedPage.getByText("Create", { exact: true }).click();
    await expect(sharedPage.locator("aside").getByText("Offline Seed Doc")).toBeVisible({
      timeout: 10_000,
    });
    await openDocument(sharedPage, "Offline Seed Doc");

    await expect
      .poll(async () => (await offlineKeyStoreKeys(sharedPage, "refmd-offline-key:kek:")).length, {
        timeout: 30_000,
        message: "workspace KEK was not cached for offline document creation",
      })
      .toBeGreaterThan(0);

    apiBlock = await blockApiRequests(sharedPage);
    await sharedPage.context().setOffline(true);
    await sharedPage.evaluate(() => window.dispatchEvent(new Event("offline")));
    await expect
      .poll(() => sharedPage.evaluate(() => navigator.onLine), {
        timeout: 10_000,
        message: "browser did not enter offline mode",
      })
      .toBe(false);
    await sharedPage.waitForTimeout(2_000);
  });

  test("creating a document while offline stores it in offline-created", async () => {
    test.setTimeout(60_000);

    await sharedPage.locator("aside button").first().click();
    await sharedPage.locator('input[placeholder="Document title"]').fill("Offline Created Doc");
    await sharedPage.getByText("Create", { exact: true }).click();

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "offline-created")).length, {
        timeout: 10_000,
        message: "offline-created entry was not persisted",
      })
      .toBeGreaterThan(0);

    const [offlineCreatedId] = await indexedDbKeys(sharedPage, "offline-created");
    if (!offlineCreatedId) {
      throw new Error("offline-created entry id was not found");
    }
    await sharedPage.evaluate((documentId) => {
      window.history.pushState({}, "", `/document/${documentId}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, offlineCreatedId);
    await focusMarkdownEditor(sharedPage);
    await sharedPage.keyboard.insertText(OFFLINE_CREATED_TEXT);
    await expectEditorTextContains(sharedPage, OFFLINE_CREATED_TEXT, 10_000);
    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "pending-changes")).includes(offlineCreatedId), {
        timeout: 10_000,
        message: "offline-created edits were not persisted to pending changes before reconnect",
      })
      .toBe(true);
  });

  test("offline-created documents sync automatically after reconnect without breaking the open editor", async () => {
    test.setTimeout(180_000);

    await apiBlock?.unblock();
    apiBlock = null;
    await sharedPage.context().setOffline(false);
    await expect
      .poll(() => sharedPage.evaluate(() => navigator.onLine), {
        timeout: 10_000,
        message: "browser did not leave offline mode",
      })
      .toBe(true);
    await expect
      .poll(
        () =>
          sharedPage.evaluate(async () => {
            try {
              await fetch("/api/auth/me", { credentials: "same-origin", cache: "no-store" });
              return true;
            } catch {
              return false;
            }
          }),
        {
          timeout: 10_000,
          message: "server was not reachable after reconnect",
        },
      )
      .toBe(true);
    await sharedPage.evaluate(() => window.dispatchEvent(new Event("online")));
    await sharedPage.evaluate(() => window.dispatchEvent(new Event("focus")));
    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(sharedPage);

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "offline-created")).length, {
        timeout: 60_000,
        message: `offline-created queue did not drain after reconnect; clientLogs=${JSON.stringify(
          await clientDiagnostics(sharedPage),
        )}; entries=${JSON.stringify(await offlineCreatedDiagnostics(sharedPage))}`,
      })
      .toBe(0);

    await expect
      .poll(
        async () =>
          sharedPage.evaluate(() => ({
            hasEditor: !!document.querySelector(".cm-content, .ProseMirror"),
            failedToLoad: document.body.textContent?.includes("Failed to load document") ?? false,
          })),
        {
          timeout: 20_000,
          message: "open offline-created document did not recover cleanly after reconnect",
        },
      )
      .toEqual({
        hasEditor: true,
        failedToLoad: false,
      });
  });

  test("synced offline-created documents survive reload and can be opened", async () => {
    test.setTimeout(180_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(sharedPage);

    const editorVisibleAfterReload = await sharedPage
      .locator(".cm-content, .ProseMirror")
      .first()
      .isVisible({ timeout: 5_000 })
      .catch(() => false);

    if (!editorVisibleAfterReload) {
      const createdDocument = sharedPage.locator("aside").getByText("Offline Created Doc");
      if (!(await createdDocument.isVisible({ timeout: 30_000 }).catch(() => false))) {
        await sharedPage.reload({ waitUntil: "domcontentloaded" });
        await waitForWorkspaceReady(sharedPage);
      }
      await expect(createdDocument).toBeVisible({ timeout: 30_000 });
      await openDocument(sharedPage, "Offline Created Doc");
    }

    await expectEditorTextContains(sharedPage, OFFLINE_CREATED_TEXT);
  });
});
