import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openSettings, selectSettingsTab } from "../../support/settings";

test("secure logout exposes incomplete cleanup in the login redirect", async ({ browser }) => {
  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();

  try {
    await registerAccount(page, "Secure Logout E2E");
    await page.evaluate(() => {
      if (!window.__refmdE2ESeedRetryingSecureCleanup) {
        throw new Error("secure cleanup retry E2E hook is unavailable");
      }
      window.__refmdE2ESeedRetryingSecureCleanup();
    });
    let logoutAttempt = 0;
    await page.route("**/api/auth/logout", async (route) => {
      logoutAttempt += 1;
      if (logoutAttempt === 1) {
        await route.abort("failed");
        return;
      }
      await route.continue();
    });

    await openSettings(page);
    await selectSettingsTab(page, "Account");
    await page.getByRole("button", { name: "Log out" }).click({ timeout: 10_000 });

    const confirmation = page
      .locator('[role="dialog"]')
      .filter({ has: page.getByRole("heading", { name: "Log out" }) });
    await expect(confirmation).toBeVisible({ timeout: 10_000 });
    await expect(confirmation.getByRole("checkbox")).toBeChecked();
    await confirmation.getByText("Keep credentials on this device", { exact: true }).click();
    await expect(confirmation.getByRole("checkbox")).not.toBeChecked();
    const logoutRequest = page.waitForRequest(
      (request) => request.method() === "POST" && request.url().endsWith("/api/auth/logout"),
    );
    await confirmation.getByRole("button", { name: "Log out" }).click({ timeout: 10_000 });
    expect((await logoutRequest).postDataJSON()).toMatchObject({ clear_mount_session: true });

    await expect(page).toHaveURL(/\/auth\/login\?logout_incomplete=true$/, {
      timeout: 30_000,
    });
    await expect(page.getByText("Retry secure cleanup", { exact: true })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByLabel("Email")).toHaveCount(0);

    await openLoginAfterLogout(page);
    await expect(page.getByText("Retry secure cleanup", { exact: true })).toBeVisible();
    for (const blockedPath of [
      "/auth/register",
      "/auth/recovery",
      "/auth/password-reset",
      "/devices/register",
    ]) {
      await test.step(`block authentication entry ${blockedPath}`, async () => {
        await page.goto(blockedPath, { waitUntil: "commit" });
        await expect(page).toHaveURL(/\/auth\/login\?logout_incomplete=true$/);
        await page.waitForLoadState("domcontentloaded");
        await expect(page.getByText("Retry secure cleanup", { exact: true })).toBeVisible({
          timeout: 30_000,
        });
        await expect(page.getByLabel("Email")).toHaveCount(0);
      });
    }

    const retryLogoutRequests = Promise.all([
      page.waitForRequest(
        (request) =>
          request.method() === "POST" &&
          request.url().endsWith("/api/auth/logout") &&
          request.headers()["x-refmd-session-scope"] === "share",
      ),
      page.waitForRequest(
        (request) =>
          request.method() === "POST" &&
          request.url().endsWith("/api/auth/logout") &&
          request.headers()["x-refmd-session-scope"] !== "share",
      ),
    ]);
    await page.getByRole("button", { name: "Retry secure cleanup" }).click();
    await retryLogoutRequests;
    await expect(page.getByLabel("Email")).toBeVisible({ timeout: 30_000 });
    await expect(
      page.evaluate(() => ({
        attempts: window.__refmdE2ESecureCleanupAttempts,
        pending: localStorage.getItem("e2e-secure-cleanup-retry-pending"),
      })),
    ).resolves.toEqual({ attempts: 2, pending: null });
  } finally {
    await context.close();
  }
});

test("secure logout deletes every registered browser persistence surface", async ({ browser }) => {
  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();

  try {
    await registerAccount(page, "Secure Logout Success E2E");
    const seededPersistence = await page.evaluate(async () => {
      if (!window.__refmdSeedSecureLogoutPersistence) {
        throw new Error("secure logout persistence E2E hook is unavailable");
      }
      return window.__refmdSeedSecureLogoutPersistence();
    });
    await expectRegisteredPersistenceSeeded(page, seededPersistence);
    const { databaseNames: registeredDatabaseNames } = seededPersistence;
    await page.evaluate(() => {
      if (!window.__refmdE2ESetPreferredSessionScope) {
        throw new Error("session scope E2E hook is unavailable");
      }
      window.__refmdE2ESetPreferredSessionScope("share");
    });

    await openSettings(page);
    await selectSettingsTab(page, "Account");
    await page.getByRole("button", { name: "Log out" }).click({ timeout: 10_000 });
    const confirmation = page
      .locator('[role="dialog"]')
      .filter({ has: page.getByRole("heading", { name: "Log out" }) });
    await expect(confirmation).toBeVisible({ timeout: 10_000 });
    await expect(confirmation.getByRole("checkbox")).toBeChecked();
    await confirmation.getByText("Keep credentials on this device", { exact: true }).click();
    await expect(confirmation.getByRole("checkbox")).not.toBeChecked();
    const logoutRequests = Promise.all([
      page.waitForRequest(
        (request) =>
          request.method() === "POST" &&
          request.url().endsWith("/api/auth/logout") &&
          request.headers()["x-refmd-session-scope"] === "share",
      ),
      page.waitForRequest(
        (request) =>
          request.method() === "POST" &&
          request.url().endsWith("/api/auth/logout") &&
          request.headers()["x-refmd-session-scope"] !== "share",
      ),
    ]);
    await confirmation.getByRole("button", { name: "Log out" }).click({ timeout: 10_000 });
    for (const request of await logoutRequests) {
      expect(request.postDataJSON()).toMatchObject({ clear_mount_session: true });
    }

    await expect(page).toHaveURL(/\/auth\/login$/, { timeout: 60_000 });
    await expect(page).not.toHaveURL(/logout_incomplete/);
    await assertRegisteredPersistenceSurfacesDeleted(page, registeredDatabaseNames);

    await openLoginAfterLogout(page);
    await expect(page).toHaveURL(/\/auth\/login$/, { timeout: 30_000 });
    await assertNoRegisteredSecretsReinitialized(page, registeredDatabaseNames);
  } finally {
    await context.close();
  }
});

test("ordinary Back to Login preserves registered durable persistence", async ({ browser }) => {
  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();

  try {
    await registerAccount(page, "Back to Login Persistence E2E");
    const seededPersistence = await page.evaluate(async () => {
      if (!window.__refmdSeedSecureLogoutPersistence) {
        throw new Error("secure logout persistence E2E hook is unavailable");
      }
      return window.__refmdSeedSecureLogoutPersistence();
    });
    await expectRegisteredPersistenceSeeded(page, seededPersistence);

    const logoutRequest = page.waitForRequest(
      (request) => request.method() === "POST" && request.url().endsWith("/api/auth/logout"),
    );
    await page.goto("/auth/recovery", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Back to Login" }).click();
    expect((await logoutRequest).postDataJSON()).toMatchObject({ clear_mount_session: false });

    await expect(page).toHaveURL(/\/auth\/login$/, { timeout: 30_000 });
    await assertRegisteredDurablePersistencePreserved(page, seededPersistence.databaseNames);

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(/\/auth\/login$/, { timeout: 30_000 });
    await assertRegisteredDurablePersistencePreserved(page, seededPersistence.databaseNames);
  } finally {
    await context.close();
  }
});

async function expectRegisteredPersistenceSeeded(
  page: import("@playwright/test").Page,
  seeded: { databaseNames: readonly string[]; verified: Record<string, boolean> },
) {
  expect(seeded.verified).toEqual({
    workerShare: true,
    trustPin: true,
    documentPin: true,
    pendingChange: true,
    localStorage: true,
    sessionStorage: true,
    cacheStorage: true,
  });
  const recordCounts = await countRegisteredDatabaseRecords(page, seeded.databaseNames);
  expect(recordCounts).toEqual(
    seeded.databaseNames.map((name) => ({ name, populated: true })),
  );
}

async function openLoginAfterLogout(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/auth/login", { waitUntil: "domcontentloaded" }).catch(async (error) => {
    const message = String(error);
    if (!message.includes("ERR_ABORTED") && !message.includes("NS_BINDING_ABORTED")) throw error;
    await page.waitForLoadState("domcontentloaded").catch(() => undefined);
    await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
  });
}

async function assertRegisteredPersistenceSurfacesDeleted(
  page: import("@playwright/test").Page,
  databaseNames: readonly string[],
) {
  const state = await page.evaluate(async (databaseNames) => ({
    localKeys: Object.keys(localStorage).filter(
      (key) => key.startsWith("refmd") || key.startsWith("recent-docs:") || key.startsWith("editor-mode:"),
    ),
    sessionKeys: Object.keys(sessionStorage),
    cacheNames: await caches.keys(),
    databaseNames: (await indexedDB.databases())
      .map((database) => database.name)
      .filter((name): name is string => typeof name === "string" && databaseNames.includes(name)),
  }), databaseNames);

  expect(state).toEqual({ localKeys: [], sessionKeys: [], cacheNames: [], databaseNames: [] });
}

async function assertNoRegisteredSecretsReinitialized(
  page: import("@playwright/test").Page,
  databaseNames: readonly string[],
) {
  const state = await page.evaluate(async (databaseNames) => {
    const databaseRecordCounts = await Promise.all(
      (await indexedDB.databases())
        .map((database) => database.name)
        .filter((name): name is string =>
          typeof name === "string" && databaseNames.includes(name),
        )
        .map(
        (name) =>
          new Promise<{ name: string; recordCount: number }>((resolve, reject) => {
            const request = indexedDB.open(name);
            request.onerror = () => reject(request.error);
            request.onsuccess = async () => {
              const db = request.result;
              try {
                let recordCount = 0;
                for (const storeName of Array.from(db.objectStoreNames)) {
                  recordCount += await new Promise<number>((resolveCount, rejectCount) => {
                    const countRequest = db.transaction(storeName).objectStore(storeName).count();
                    countRequest.onsuccess = () => resolveCount(countRequest.result);
                    countRequest.onerror = () => rejectCount(countRequest.error);
                  });
                }
                resolve({ name, recordCount });
              } finally {
                db.close();
              }
            };
          }),
        ),
    );

    return {
      localKeys: Object.keys(localStorage).filter(
        (key) =>
          key.startsWith("refmd") ||
          key.startsWith("recent-docs:") ||
          key.startsWith("editor-mode:"),
      ),
      sessionKeys: Object.keys(sessionStorage),
      secretCachePresent: (await caches.keys()).includes("refmd-e2e-cache"),
      databaseRecordCounts,
    };
  }, databaseNames);

  expect(state.localKeys).toEqual([]);
  expect(state.sessionKeys).toEqual([]);
  expect(state.secretCachePresent).toBe(false);
  expect(state.databaseRecordCounts).toEqual(
    state.databaseRecordCounts.map(({ name }) => ({ name, recordCount: 0 })),
  );
}

async function assertRegisteredDurablePersistencePreserved(
  page: import("@playwright/test").Page,
  databaseNames: readonly string[],
) {
  const state = await page.evaluate(async () => ({
    localSecret: localStorage.getItem("refmd-e2e-secret"),
    recentDocument: localStorage.getItem("recent-docs:e2e"),
    editorMode: localStorage.getItem("editor-mode:e2e"),
    sessionKeys: Object.keys(sessionStorage),
    secretCachePresent: (await caches.keys()).includes("refmd-e2e-cache"),
  }));

  expect(state).toEqual({
    localSecret: "local-secret",
    recentDocument: "document-secret",
    editorMode: "markdown",
    sessionKeys: [],
    secretCachePresent: true,
  });
  expect(await countRegisteredDatabaseRecords(page, databaseNames)).toEqual(
    databaseNames.map((name) => ({ name, populated: true })),
  );
}

async function countRegisteredDatabaseRecords(
  page: import("@playwright/test").Page,
  databaseNames: readonly string[],
): Promise<Array<{ name: string; populated: boolean }>> {
  return page.evaluate(async (names) => {
    const results: Array<{ name: string; populated: boolean }> = [];
    for (const name of names) {
      const request = indexedDB.open(name);
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      let recordCount = 0;
      for (const storeName of Array.from(db.objectStoreNames)) {
        recordCount += await new Promise<number>((resolve, reject) => {
          const count = db.transaction(storeName).objectStore(storeName).count();
          count.onsuccess = () => resolve(count.result);
          count.onerror = () => reject(count.error);
        });
      }
      db.close();
      results.push({ name, populated: recordCount > 0 });
    }
    return results;
  }, databaseNames);
}
