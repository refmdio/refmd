import {
  test,
  expect,
  chromium,
  firefox,
  type BrowserContext,
  type BrowserType,
} from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { registerAccount } from "../../support/auth";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import {
  e2eBaseURL,
  launchPersistentE2EContext,
} from "../../support/context";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

const requiresStaticServer = !e2eBaseURL.includes(":5173");

async function captureUiState(page: Parameters<typeof registerAccount>[0]) {
  return page.evaluate(() => ({
    selectedDocumentId: localStorage.getItem("refmd_selected_document"),
    workspaceId: localStorage.getItem("refmd_workspace_id"),
    panelCount: document.querySelectorAll("[data-panel-id]").length,
    hasEditor: !!document.querySelector(".cm-content"),
    hasNoDocumentsText: document.body.textContent?.includes("No documents open") ?? false,
  }));
}

async function waitForServiceWorker(page: Parameters<typeof registerAccount>[0]) {
  const deadline = Date.now() + 60_000;
  let lastState: unknown = null;

  while (Date.now() < deadline) {
    await page.reload({ waitUntil: "load" });
    await page.waitForTimeout(E2E_DELAYS.uiSettle);

    lastState = await page.evaluate(async () => {
      const registrations = await navigator.serviceWorker.getRegistrations();
      const registration = registrations.find(
        (entry) => new URL(entry.scope).origin === window.location.origin,
      );
      return {
        controllerPath: navigator.serviceWorker.controller
          ? new URL(navigator.serviceWorker.controller.scriptURL).pathname
          : null,
        activePath: registration?.active ? new URL(registration.active.scriptURL).pathname : null,
        cacheNames: await caches.keys(),
      };
    });

    if (
      typeof lastState === "object" &&
      lastState !== null &&
      "controllerPath" in lastState &&
      "activePath" in lastState &&
      (lastState as { controllerPath: string | null }).controllerPath === "/sw.js" &&
      (lastState as { activePath: string | null }).activePath === "/sw.js"
    ) {
      return;
    }
  }

  throw new Error(`Service worker did not take control: ${JSON.stringify(lastState)}`);
}

async function waitForOfflineDocumentCache(page: Parameters<typeof registerAccount>[0]) {
  await expect
    .poll(
      () =>
        page.evaluate(async () => {
          const openDb = (name: string) =>
            new Promise<IDBDatabase>((resolve, reject) => {
              const request = indexedDB.open(name);
              request.onsuccess = () => resolve(request.result);
              request.onerror = () => reject(request.error);
            });

          const offlineDb = await openDb("refmd-offline");
          const keyDb = await openDb("refmd-keys");

          const count = (db: IDBDatabase, storeName: string) =>
            new Promise<number>((resolve, reject) => {
              if (!db.objectStoreNames.contains(storeName)) {
                resolve(0);
                return;
              }
              const tx = db.transaction(storeName, "readonly");
              const request = tx.objectStore(storeName).count();
              request.onsuccess = () => resolve(request.result);
              request.onerror = () => reject(request.error);
            });

          const countKeysWithPrefix = (db: IDBDatabase, storeName: string, prefix: string) =>
            new Promise<number>((resolve, reject) => {
              if (!db.objectStoreNames.contains(storeName)) {
                resolve(0);
                return;
              }
              const tx = db.transaction(storeName, "readonly");
              const request = tx.objectStore(storeName).getAllKeys();
              request.onsuccess = () =>
                resolve(request.result.filter((key) => String(key).startsWith(prefix)).length);
              request.onerror = () => reject(request.error);
            });

          try {
            const [workspaces, documentIndex, documents, documentCache, dekCache] =
              await Promise.all([
                count(offlineDb, "offline-workspaces"),
                count(offlineDb, "offline-document-index"),
                count(offlineDb, "offline-documents"),
                count(offlineDb, "document-cache"),
                countKeysWithPrefix(keyDb, "keystore", "refmd-offline-key:dek:"),
              ]);
            return (
              workspaces > 0 &&
              documentIndex > 0 &&
              documents > 0 &&
              documentCache > 0 &&
              dekCache > 0
            );
          } finally {
            offlineDb.close();
            keyDb.close();
          }
        }),
      {
        timeout: 60_000,
        message: "offline workspace/document caches were not ready before browser restart",
      },
    )
    .toBe(true);
}

async function appShellCacheState(page: Parameters<typeof registerAccount>[0]) {
  return page.evaluate(async () => {
    const cache = await caches.open("app-shell-v1");
    const keys = await cache.keys();
    const paths = keys.map((req) => new URL(req.url).pathname);
    const hasIndex = paths.includes("/index.html");
    const canServeOffline = hasIndex || (await cache.match("/index.html")) !== undefined;
    return {
      count: keys.length,
      hasIndex,
      canServeOffline,
      paths: paths.slice(0, 10),
    };
  });
}

async function latestDocumentCacheUpdatedAt(page: Parameters<typeof registerAccount>[0]) {
  return page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("refmd-offline");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    try {
      if (!db.objectStoreNames.contains("document-cache")) return 0;
      return await new Promise<number>((resolve, reject) => {
        const tx = db.transaction("document-cache", "readonly");
        const request = tx.objectStore("document-cache").getAll();
        request.onsuccess = () => {
          const rows = request.result as Array<{ updatedAt?: number }>;
          resolve(Math.max(0, ...rows.map((row) => row.updatedAt ?? 0)));
        };
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
  });
}

test("service worker serves app shell after browser restart while fully offline", async ({
  browserName,
}) => {
  test.skip(!requiresStaticServer, "Requires Phoenix/static asset server, not Vite dev server");
  test.setTimeout(E2E_TIMEOUTS.offlineShell);

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "refmd-sw-e2e-"));
  let context: BrowserContext | null = null;

  try {
    const browserType: BrowserType = browserName === "firefox" ? firefox : chromium;
    context = await launchPersistentE2EContext(browserType, userDataDir, {
      acceptDownloads: true,
      headless: true,
      ...(browserType === chromium ? { args: ["--disable-web-security"] } : {}),
    });

    let page = context.pages()[0] ?? (await context.newPage());

    await registerAccount(page);
    await createDocument(page, "SW Cold Start Doc");
    await openDocument(page, "SW Cold Start Doc");

    const cacheUpdatedBeforeEdit = await latestDocumentCacheUpdatedAt(page);
    const editor = page.locator(".cm-content");
    await editor.click();
    await page.keyboard.insertText("Cold start offline content");
    await expectEditorTextContains(page, "Cold start offline content");
    await page.evaluate(() => {
      window.dispatchEvent(new Event("beforeunload"));
    });
    await expect
      .poll(() => latestDocumentCacheUpdatedAt(page), {
        timeout: 30_000,
        message: "document cache was not updated after cold-start content edit",
      })
      .toBeGreaterThan(cacheUpdatedBeforeEdit);

    await waitForServiceWorker(page);
    await waitForOfflineDocumentCache(page);

    // Ensure the fetch handler has cached /index.html via a controlled navigation
    await page.reload({ waitUntil: "load" });
    await expectEditorTextContains(page, "Cold start offline content", 60_000);

    await expect
      .poll(() => appShellCacheState(page), {
        timeout: 10_000,
        message: "app shell cache was not primed after controlled navigation",
      })
      .toMatchObject({ canServeOffline: true });
    const cacheState = await appShellCacheState(page);
    expect(cacheState.canServeOffline).toBe(true);
    expect(cacheState.count).toBeGreaterThan(1);

    await context.close();
    context = await launchPersistentE2EContext(browserType, userDataDir, {
      acceptDownloads: true,
      headless: true,
      ...(browserType === chromium ? { args: ["--disable-web-security"] } : {}),
    });

    await context.setOffline(true);
    page = context.pages()[0] ?? (await context.newPage());

    await page.goto("/dashboard", { waitUntil: "domcontentloaded", timeout: 60_000 });
    await expect
      .poll(
        () =>
          page.evaluate(async () => {
            const cache = await caches.open("app-shell-v1");
            return (await cache.keys()).length;
          }),
        { timeout: 10_000, message: "app shell cache was not available after offline restart" },
      )
      .toBeGreaterThan(1);

    const sidebar = page.locator("aside");
    const docButton = sidebar
      .getByRole("button", { name: "SW Cold Start Doc" })
      .or(sidebar.getByRole("button", { name: "Untitled" }))
      .first();

    await expect(docButton).toBeVisible({
      timeout: 60_000,
    });

    const beforeOpen = await captureUiState(page);
    await docButton.click({ timeout: 5_000 });
    await expect
      .poll(async () => (await captureUiState(page)).panelCount, {
        timeout: 5_000,
        message: `offline panel did not open; before=${JSON.stringify(beforeOpen)}`,
      })
      .toBeGreaterThan(0);
    await expect(page.locator(".cm-content")).toBeVisible({ timeout: 60_000 });
    await expectEditorTextContains(page, "Cold start offline content", 60_000);

    const offlineSwState = await page.evaluate(async () => {
      return {
        controllerPath: navigator.serviceWorker.controller
          ? new URL(navigator.serviceWorker.controller.scriptURL).pathname
          : null,
        registrations: (await navigator.serviceWorker.getRegistrations()).map((registration) =>
          registration.active ? new URL(registration.active.scriptURL).pathname : null,
        ),
      };
    });

    expect(offlineSwState.controllerPath).toBe("/sw.js");
    expect(offlineSwState.registrations).toContain("/sw.js");
  } finally {
    await context?.close().catch(() => {});
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
});
