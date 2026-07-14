import { expect, test } from "@playwright/test";
import {
  login,
  logout,
  registerAccountWithRecoveryPhrase,
  TEST_PASSWORD,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument } from "../../support/documents";
import { openSettings, selectSettingsTab } from "../../support/settings";
import { createWorkspace, waitForWorkspaceReady } from "../../support/workspace";

test("overdue identity rotation rewraps every workspace and survives reload", async ({ browser }) => {
  test.setTimeout(900_000);
  const context = await newE2EContext(browser, { bypassCSP: true });
  const secondaryContext = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
    window.__refmdE2EClientLogs = [];
    window.addEventListener("refmd:client-log", (event) => {
      window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
    });
  });
  await secondaryContext.addInitScript(() => {
    window.__REFMD_E2E__ = true;
    window.__refmdE2EDisableIdentityRotationMonitor = true;
    window.__refmdE2EClientLogs = [];
    window.addEventListener("refmd:client-log", (event) => {
      window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
    });
  });
  const page = await context.newPage();
  let secondaryPage = await secondaryContext.newPage();
  const rotationResponses: Array<{ path: string; status: number; body: unknown }> = [];
  const failedResponses: Array<{ path: string; status: number; body: unknown }> = [];
  const browserErrors: string[] = [];
  const secondaryErrors: string[] = [];
  const secondaryRecoveryResponses: Array<{ path: string; status: number; body: unknown }> = [];

  page.on("pageerror", (error) => browserErrors.push(`pageerror:${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(`console:${message.text()}`);
  });

  page.on("response", async (response) => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith("/api/") && response.status() >= 400) {
      failedResponses.push({
        path,
        status: response.status(),
        body: await response.json().catch(() => null),
      });
    }
    if (!path.includes("/api/encryption/identity-rotation")) return;
    rotationResponses.push({
      path,
      status: response.status(),
      body: await response.json().catch(() => null),
    });
  });
  secondaryPage.on("pageerror", (error) => secondaryErrors.push(`pageerror:${error.message}`));
  secondaryPage.on("console", (message) => {
    if (message.type() === "error") secondaryErrors.push(`console:${message.text()}`);
  });
  secondaryPage.on("response", async (response) => {
    const path = new URL(response.url()).pathname;
    if (!path.includes("recovery") && response.status() < 400) return;
    secondaryRecoveryResponses.push({
      path,
      status: response.status(),
      body: response.status() >= 400 ? await response.json().catch(() => null) : null,
    });
  });
  try {
    const { email, mnemonic } = await registerAccountWithRecoveryPhrase(
      page,
      "Identity Rotation E2E",
    );
    const workspaceName = `Identity Rotation ${Date.now()}`;
    await createWorkspace(page, workspaceName);
    const documentTitle = `Identity Rotation Document ${Date.now()}`;
    await createDocument(page, documentTitle);
    await page.locator("aside").getByText(documentTitle, { exact: true }).click();
    await expect(
      page.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    const documentPath = new URL(page.url()).pathname;
    expect(documentPath).toMatch(/^\/document\/[0-9a-f-]+$/);
    const documentId = documentPath.split("/").at(-1)!;
    let originalSecondaryWsToken = "";
    let seededSecondaryDatabaseNames: readonly string[] = [];

    const originalSecondaryDevice = await test.step("approve secondary device", async () => {
      await login(secondaryPage, email, { allowDeviceRegistration: true });
      await expect(secondaryPage).toHaveURL(/devices\/register/, { timeout: 60_000 });
      const approveButton = page.getByRole("button", { name: /Emojis Match.*Approve/i });
      await expect(approveButton).toBeVisible({ timeout: 120_000 });
      const umkDistribution = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          /\/api\/devices\/[^/]+\/keys\/umk$/.test(new URL(response.url()).pathname) &&
          response.status() === 201,
        { timeout: 120_000 },
      );
      await approveButton.click();
      await umkDistribution;
      await expect(secondaryPage).toHaveURL(/dashboard/, { timeout: 120_000 });
      await secondaryPage.reload({ waitUntil: "domcontentloaded" });
      return persistedDevice(secondaryPage);
    });

    await test.step("open live document on secondary device", async () => {
      await secondaryPage.goto(documentPath, { waitUntil: "domcontentloaded" });
      await expect(
        secondaryPage.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
      ).toBeVisible({ timeout: 120_000 });
      await expect
        .poll(
          () =>
            secondaryPage.evaluate(
              (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
              documentId,
            ),
          { timeout: 60_000 },
        )
        .toBe("joined");
      originalSecondaryWsToken = await secondaryPage.evaluate(async () => {
        const response = await fetch("/api/auth/ws-token", { method: "POST" });
        if (!response.ok) throw new Error(`ws_token_failed:${response.status}`);
        const payload = (await response.json()) as { token?: unknown };
        if (typeof payload.token !== "string") throw new Error("ws_token_missing");
        return payload.token;
      });
      const seeded = await secondaryPage.evaluate(async () => {
        const seed = (
          window as typeof window & {
            __refmdSeedSecureLogoutPersistence?: () => Promise<{
              databaseNames: readonly string[];
              verified: Record<string, boolean>;
            }>;
          }
        ).__refmdSeedSecureLogoutPersistence;
        if (!seed) throw new Error("identity_wipe_e2e_seed_hook_missing");
        return seed();
      });
      expect(Object.values(seeded.verified).every(Boolean)).toBe(true);
      seededSecondaryDatabaseNames = seeded.databaseNames;
    });

    try {
      await expect
        .poll(
          () =>
            rotationResponses.find(
              (entry) => entry.path.endsWith("/finalize") && entry.status === 200,
            )?.body,
          { timeout: 300_000, intervals: [250, 500, 1_000] },
        )
        .toMatchObject({
          current_key_version: 2,
          pending_key_version: null,
          required_workspace_count: 2,
          envelopes_complete: false,
        });
    } catch (error) {
      const clientLogs = await page.evaluate(() => window.__refmdE2EClientLogs ?? []);
      throw new Error(
        `identity rotation did not finalize: ${JSON.stringify({ rotationResponses, failedResponses, browserErrors, clientLogs })}\n${String(error)}`,
      );
    }

    await expect
      .poll(
        () =>
          secondaryPage.evaluate(async () => ({
            settingsStatus: await fetch("/api/settings").then((response) => response.status),
          })),
        { timeout: 60_000 },
      )
      .toMatchObject({ settingsStatus: 401 });
    await expect
      .poll(
        () =>
          secondaryPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState === "joined",
            documentId,
          ),
        { timeout: 60_000 },
      )
      .toBe(false);
    await expectStaleWebSocketRejected(secondaryPage, originalSecondaryWsToken);
    await expect
      .poll(
        () =>
          secondaryPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) !== undefined,
            documentId,
          ),
        { timeout: 30_000 },
      )
      .toBe(true);

    expect(
      rotationResponses.some(
        (entry) => entry.path.endsWith("/prepare") && entry.status === 200,
      ),
    ).toBe(true);
    expect(
      rotationResponses.some(
        (entry) =>
          entry.path === "/api/encryption/identity-rotation" &&
          entry.status === 200 &&
          typeof entry.body === "object" &&
          entry.body !== null &&
          "required_workspace_count" in entry.body &&
          entry.body.required_workspace_count === 2 &&
          "covered_workspace_count" in entry.body &&
          entry.body.covered_workspace_count === 2 &&
          "envelopes_complete" in entry.body &&
          entry.body.envelopes_complete === true,
      ),
    ).toBe(true);

    await page.reload();
    await expect(page).toHaveURL(documentPath, { timeout: 60_000 });
    await expect(
      page.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    await expect(page.getByText("Key Verification Failed")).toHaveCount(0);
    await expect(page.getByText("Temporarily Unavailable")).toHaveCount(0);

    try {
      await logout(page);
    } catch (error) {
      const clientLogs = await page.evaluate(() => window.__refmdE2EClientLogs ?? []);
      throw new Error(
        `dashboard reload after rotation failed: ${JSON.stringify({ failedResponses, browserErrors, clientLogs })}\n${String(error)}`,
      );
    }
    await page.close();
    const loginPage = await context.newPage();
    try {
      await login(loginPage, email);
    } catch (error) {
      const diagnostics = await loginPage.evaluate(() => ({
        body: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1_500),
        clientLogs: window.__refmdE2EClientLogs ?? [],
        url: window.location.href,
      }));
      throw new Error(
        `password login after rotation failed: ${JSON.stringify({ diagnostics, failedResponses, browserErrors })}\n${String(error)}`,
      );
    }
    await expect(loginPage).toHaveURL(/dashboard/, { timeout: 60_000 });
    await expect(loginPage.getByText("Key Verification Failed")).toHaveCount(0);

    await expect(
      secondaryPage.evaluate(
        async ({ accountEmail, accountPassword }) => {
          const runLogin = (
            window as typeof window & {
              __refmdE2ELoginForIdentityRecovery?: (
                email: string,
                password: string,
              ) => Promise<string>;
            }
          ).__refmdE2ELoginForIdentityRecovery;
          if (!runLogin) throw new Error("identity_recovery_login_hook_missing");
          return runLogin(accountEmail, accountPassword);
        },
        { accountEmail: email, accountPassword: TEST_PASSWORD },
      ),
    ).resolves.toBe("identity_recovery_required");
    await expect
      .poll(
        () =>
          secondaryPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            documentId,
          ),
        { timeout: 30_000 },
      )
      .toBeNull();
    await expectIdentityRecoveryPersistenceWiped(
      secondaryPage,
      seededSecondaryDatabaseNames,
      originalSecondaryDevice.key,
    );
    await secondaryPage.goto("/auth/recovery", { waitUntil: "domcontentloaded" });
    await expect(secondaryPage).toHaveURL(/auth\/recovery/, { timeout: 60_000 });
    await expect(
      secondaryPage.evaluate(() =>
        Promise.all([
          fetch("/api/settings").then((response) => response.status),
          fetch("/api/auth/me").then((response) => response.status),
          fetch("/api/auth/recovery").then((response) => response.status),
        ]),
      ),
    ).resolves.toEqual([401, 200, 200]);

    await secondaryPage.locator('input[placeholder="word"]').first().fill(mnemonic);
    await secondaryPage.getByRole("button", { name: "Recover Account" }).click();
    try {
      await expect
        .poll(
          async () => {
            if (new URL(secondaryPage.url()).pathname === "/dashboard") return "dashboard";
            const alert = secondaryPage.getByRole("alert");
            if (await alert.isVisible().catch(() => false)) {
              return `recovery_error:${(await alert.textContent())?.trim()}`;
            }
            return "recovering";
          },
          { timeout: 120_000 },
        )
        .toBe("dashboard");
    } catch (error) {
      const diagnostics = await secondaryPage.evaluate(() => ({
        body: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 2_000),
        clientLogs: window.__refmdE2EClientLogs ?? [],
        url: window.location.href,
      }));
      throw new Error(
        `same-context identity recovery did not complete: ${JSON.stringify({ diagnostics, secondaryErrors, secondaryRecoveryResponses })}\n${String(error)}`,
      );
    }
    const replacementSecondaryDevice = await persistedDevice(secondaryPage);
    expect(replacementSecondaryDevice.key).toBe(originalSecondaryDevice.key);
    expect(replacementSecondaryDevice.id).not.toBe(originalSecondaryDevice.id);
    await secondaryPage.reload({ waitUntil: "domcontentloaded" });
    await expect(secondaryPage).toHaveURL(/dashboard/, { timeout: 60_000 });
    await secondaryPage.goto(documentPath, { waitUntil: "domcontentloaded" });
    await expect(
      secondaryPage.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    await expect
      .poll(
        () =>
          secondaryPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
            documentId,
          ),
        { timeout: 60_000 },
      )
      .toBe("joined");

    const replacedContext = await newE2EContext(browser, { bypassCSP: true });
    try {
      await replacedContext.addInitScript(
        ({ key, id }) => localStorage.setItem(key, id),
        originalSecondaryDevice,
      );
      const replacedPage = await replacedContext.newPage();
      await loginIntoRecovery(replacedPage, email);
      await expect(replacedPage).toHaveURL(/auth\/recovery/, { timeout: 60_000 });
      await expect(
        replacedPage.evaluate(() => fetch("/api/settings").then((response) => response.status)),
      ).resolves.toBe(401);
    } finally {
      await replacedContext.close();
    }
  } finally {
    await secondaryContext.close();
    await context.close();
  }
});

test("persisted guest identity rotates before overdue admission and survives reload", async ({
  browser,
}) => {
  const deadlineSeconds = Number(process.env.REFMD_IDENTITY_ROTATION_SECONDS);
  expect(
    Number.isInteger(deadlineSeconds) && deadlineSeconds >= 5 && deadlineSeconds <= 60,
    "prepare the served app and E2E runner with REFMD_IDENTITY_ROTATION_SECONDS between 5 and 60",
  ).toBe(true);
  test.setTimeout(300_000);

  const ownerContext = await newE2EContext(browser, { bypassCSP: true });
  const guestContext = await newE2EContext(browser, { bypassCSP: true });
  const rotationResponses: Array<{ path: string; status: number; body: unknown }> = [];
  const browserErrors: string[] = [];
  try {
    const ownerPage = await ownerContext.newPage();
    await registerAccountWithRecoveryPhrase(ownerPage, "Guest Identity Rotation Owner");
    const documentTitle = `Guest Identity Rotation ${Date.now()}`;
    await createDocument(ownerPage, documentTitle);
    await openSettings(ownerPage);
    await selectSettingsTab(ownerPage, "Workspace");
    const guestInvites = ownerPage.getByTestId("guest-invites-section");
    if (!(await guestInvites.getByRole("button", { name: "Invite Guest" }).isVisible())) {
      await guestInvites.getByRole("group", { name: "Allow guest invites" }).click();
      await guestInvites.getByRole("button", { name: "Save" }).click();
      await expect(guestInvites.getByRole("button", { name: "Invite Guest" })).toBeVisible({
        timeout: 30_000,
      });
    }
    await guestInvites.getByRole("button", { name: "Invite Guest" }).click();
    const inviteDialog = ownerPage
      .locator('[role="dialog"]')
      .filter({ has: ownerPage.getByRole("heading", { name: "Invite Guest" }) });
    await inviteDialog.getByRole("button", { name: "Create Invitation" }).click();
    const inviteInput = inviteDialog.locator("input[readonly]").first();
    await expect(inviteInput).toHaveValue(/\/invite#it=.+&ib=.+/, { timeout: 60_000 });
    const inviteLink = await inviteInput.inputValue();

    await guestContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      window.__refmdE2EClientLogs = [];
      window.addEventListener("refmd:client-log", (event) => {
        window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
      });
    });
    const guestPage = await guestContext.newPage();
    guestPage.on("pageerror", (error) => browserErrors.push(`pageerror:${error.message}`));
    guestPage.on("console", (message) => {
      if (message.type() === "error") browserErrors.push(`console:${message.text()}`);
    });
    guestPage.on("response", async (response) => {
      const path = new URL(response.url()).pathname;
      if (!path.includes("/api/encryption/identity-rotation")) return;
      rotationResponses.push({
        path,
        status: response.status(),
        body: await response.json().catch(() => null),
      });
    });
    await guestPage.goto(inviteLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage.getByRole("button", { name: "Continue as Guest" })).toBeVisible({
      timeout: 30_000,
    });
    await guestPage.getByRole("button", { name: "Continue as Guest" }).click();
    await expect(guestPage).toHaveURL(/\/dashboard/, { timeout: 60_000 });
    await waitForWorkspaceReady(guestPage);
    await guestPage.locator("aside").getByText(documentTitle, { exact: true }).click();
    await expect(
      guestPage.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    const documentPath = new URL(guestPage.url()).pathname;
    expect(documentPath).toMatch(/^\/document\/[0-9a-f-]+$/);
    const documentId = documentPath.split("/").at(-1)!;
    await expect
      .poll(
        () =>
          guestPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
            documentId,
          ),
        { timeout: 60_000 },
      )
      .toBe("joined");

    try {
      await expect
        .poll(
          () =>
            rotationResponses.find(
              (entry) => entry.path.endsWith("/finalize") && entry.status === 200,
            )?.body,
          { timeout: 90_000, intervals: [250, 500, 1_000] },
        )
        .toMatchObject({ current_key_version: 2, pending_key_version: null });
    } catch (error) {
      const clientLogs = await guestPage.evaluate(() => window.__refmdE2EClientLogs ?? []);
      throw new Error(
        `guest identity rotation did not finalize: ${JSON.stringify({ rotationResponses, browserErrors, clientLogs })}\n${String(error)}`,
      );
    }

    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(
      guestPage.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    await expect
      .poll(
        () =>
          guestPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
            documentId,
          ),
        { timeout: 60_000 },
      )
      .toBe("joined");

    await guestPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(guestPage);
    await guestPage.locator("aside").getByText(documentTitle, { exact: true }).click();
    await expect(guestPage).toHaveURL(documentPath, { timeout: 60_000 });
    await expect(
      guestPage.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
    ).toBeVisible({ timeout: 120_000 });
    await expect(guestPage.getByText("Key Verification Failed")).toHaveCount(0);
    await expect(guestPage.getByText("Temporarily Unavailable")).toHaveCount(0);
  } finally {
    await guestContext.close().catch(() => {});
    await ownerContext.close().catch(() => {});
  }
});

async function loginIntoRecovery(
  page: import("@playwright/test").Page,
  email: string,
) {
  await page.goto("/auth/login");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
}

async function persistedDevice(
  page: import("@playwright/test").Page,
): Promise<{ key: string; id: string }> {
  return page.evaluate(() => {
    const key = Object.keys(localStorage).find((candidate) =>
      candidate.startsWith("refmd-device-id:"),
    );
    if (!key) throw new Error("persisted_device_id_missing");
    const id = localStorage.getItem(key);
    if (!id) throw new Error("persisted_device_id_missing");
    return { key, id };
  });
}

async function expectIdentityRecoveryPersistenceWiped(
  page: import("@playwright/test").Page,
  databaseNames: readonly string[],
  predecessorDeviceStorageKey: string,
) {
  const state = await page.evaluate(
    async ({ registeredDatabaseNames, deviceStorageKey }) => {
      const databaseRecordCounts = await Promise.all(
        (await indexedDB.databases())
          .map((database) => database.name)
          .filter(
            (name): name is string =>
              typeof name === "string" && registeredDatabaseNames.includes(name),
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
                        const countRequest = db
                          .transaction(storeName)
                          .objectStore(storeName)
                          .count();
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
        predecessorDeviceId: localStorage.getItem(deviceStorageKey),
        localSecret: localStorage.getItem("refmd-e2e-secret"),
        recentDocument: localStorage.getItem("recent-docs:e2e"),
        editorMode: localStorage.getItem("editor-mode:e2e"),
        logoutIncomplete: localStorage.getItem("logout-incomplete"),
        sessionSecret: sessionStorage.getItem("refmd-e2e-session"),
        cachePresent: (await caches.keys()).includes("refmd-e2e-cache"),
        databaseRecordCounts,
      };
    },
    { registeredDatabaseNames: databaseNames, deviceStorageKey: predecessorDeviceStorageKey },
  );

  expect(state).toMatchObject({
    predecessorDeviceId: null,
    localSecret: null,
    recentDocument: null,
    editorMode: null,
    logoutIncomplete: null,
    sessionSecret: null,
    cachePresent: false,
  });
  expect(state.databaseRecordCounts).toEqual(
    state.databaseRecordCounts.map(({ name }) => ({ name, recordCount: 0 })),
  );
}

async function expectStaleWebSocketRejected(
  page: import("@playwright/test").Page,
  token: string,
) {
  const result = await page.evaluate(async (staleToken) => {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${scheme}//${location.host}/socket/websocket?token=${encodeURIComponent(staleToken)}&vsn=2.0.0`;

    return new Promise<"closed" | "opened">((resolve) => {
      const socket = new WebSocket(url);
      const timeout = window.setTimeout(() => {
        socket.close();
        resolve("opened");
      }, 5_000);
      socket.addEventListener("open", () => {
        window.clearTimeout(timeout);
        socket.close();
        resolve("opened");
      });
      socket.addEventListener("close", () => {
        window.clearTimeout(timeout);
        resolve("closed");
      });
    });
  }, token);

  expect(result).toBe("closed");
}
