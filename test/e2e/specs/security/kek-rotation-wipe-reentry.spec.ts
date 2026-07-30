import { expect, test, type Page } from "@playwright/test";
import { registerAccount, TEST_PASSWORD } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument, openDocument } from "../../support/documents";
import {
  deviceRowByName,
  openSecuritySettings,
  renameCurrentDevice,
} from "../../support/security-settings";

test("offline device acknowledges KEK wipe and reenters with the current key", async ({
  browser,
}) => {
  test.setTimeout(600_000);
  const ownerContext = await newE2EContext(browser);
  const offlineContext = await newE2EContext(browser);
  const targetContext = await newE2EContext(browser);
  const secondTargetContext = await newE2EContext(browser);
  await Promise.all(
    [ownerContext, offlineContext, targetContext, secondTargetContext].map((context) =>
      context.addInitScript(() => {
        window.__REFMD_E2E__ = true;
        window.__refmdE2EClientLogs = [];
        window.addEventListener("refmd:client-log", (event) => {
          window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
        });
      }),
    ),
  );
  const owner = await ownerContext.newPage();
  const offline = await offlineContext.newPage();
  const target = await targetContext.newPage();
  const secondTarget = await secondTargetContext.newPage();
  const kekResponses: Array<{ method: string; path: string; status: number; body: string }> = [];
  const wipeResponses: Array<{ method: string; path: string; status: number; body: string }> = [];
  owner.on("response", async (response) => {
    const path = new URL(response.url()).pathname;
    if (!path.includes("/kek-rotation") && !path.includes("/rotations/")) return;
    kekResponses.push({
      method: response.request().method(),
      path,
      status: response.status(),
      body: (await response.text().catch(() => "<unavailable>")).slice(0, 500),
    });
  });
  offline.on("response", async (response) => {
    const path = new URL(response.url()).pathname;
    if (!path.includes("wipe-requirement")) return;
    wipeResponses.push({
      method: response.request().method(),
      path,
      status: response.status(),
      body: (await response.text().catch(() => "<unavailable>")).slice(0, 500),
    });
  });
  const title = `KEK Wipe ${Date.now()}`;
  const baselineText = `baseline-before-kek-rotation-${Date.now()}`;
  const wipedOfflineText = `offline-kek-change-that-must-be-wiped-${Date.now()}`;
  const postWipeText = `offline-after-kek-rotation-${Date.now()}`;

  try {
    const email = await registerAccount(owner, "KEK Wipe E2E");
    await test.step("create owner document", async () => {
      await createDocument(owner, title);
      await openDocument(owner, title);
    });
    const documentPath = new URL(owner.url()).pathname;
    const documentId = documentPath.split("/").at(-1)!;
    await waitForJoined(owner, documentId);
    await appendTextThroughVisibleEditor(owner, baselineText);
    await flushDocumentSync(owner, documentId);

    await test.step("approve and prepare offline device", async () => {
      await registerAndApprove(owner, offline, email);
      await offline.goto(documentPath, { waitUntil: "domcontentloaded" });
      await waitForJoined(offline, documentId);
      await expectVisibleEditorTextContains(offline, baselineText, 60_000);
      await offlineContext.setOffline(true);
      await appendTextThroughVisibleEditor(offline, wipedOfflineText);
      await flushDocumentSync(offline, documentId);
      await expect.poll(() => pendingExists(offline, documentId), { timeout: 30_000 }).toBe(true);
    });

    await test.step("approve and rename both revocation targets", async () => {
      await registerAndApprove(owner, target, email);
      await renameCurrentDevice(target, "KEK Revocation Target 1");
      await registerAndApprove(owner, secondTarget, email);
      await renameCurrentDevice(secondTarget, "KEK Revocation Target 2");
    });

    await test.step("complete two security KEK and DEK rotations while offline", async () => {
      await revokeTargetAndCompleteRotations(
        owner,
        "KEK Revocation Target 1",
        documentPath,
        documentId,
        kekResponses,
      );
      await revokeTargetAndCompleteRotations(
        owner,
        "KEK Revocation Target 2",
        documentPath,
        documentId,
        kekResponses,
      );
    });

    await test.step("acknowledge wipe and reenter from offline device", async () => {
      const currentWorkspaceKeys = offline.waitForResponse(
        (response) =>
          response.request().method() === "GET" &&
          /\/api\/encryption\/workspaces\/[^/]+\/keys$/.test(new URL(response.url()).pathname) &&
          response.status() === 200,
        { timeout: 240_000 },
      );
      await offlineContext.setOffline(false);
      await offline.reload({ waitUntil: "domcontentloaded" });
      try {
        await expect
          .poll(() => workspaceWipeResponses(wipeResponses, "POST", 200).length, {
            timeout: 120_000,
          })
          .toBe(2);
        await expect
          .poll(() => documentWipeResponses(wipeResponses, documentId, "POST", 200).length, {
            timeout: 120_000,
          })
          .toBe(2);
        const requirements = workspaceWipeResponses(wipeResponses, "GET", 200)
          .map(
            (response) =>
              JSON.parse(response.body) as {
                old_key_version: number;
                required_kek_version: number;
              },
          )
          .sort((left, right) => left.required_kek_version - right.required_kek_version);
        expect(requirements.map((item) => item.required_kek_version)).toEqual([2, 3]);
        expect(requirements.map((item) => item.old_key_version)).toEqual([1, 2]);
        const requiredKekVersion = requirements.at(-1)!.required_kek_version;
        const keysResponse = await currentWorkspaceKeys;
        const keys = (await keysResponse.json()) as {
          current_kek_version: number;
          keys: Array<{ key_version: number }>;
        };
        expect(keys.current_kek_version).toBe(requiredKekVersion);
        expect(keys.keys.length).toBeGreaterThan(0);
        expect(keys.keys.every((key) => key.key_version === requiredKekVersion)).toBe(true);
        expect(keys.keys.some((key) => key.key_version < requiredKekVersion)).toBe(false);
      } catch (error) {
        const visibleText = (await offline.locator("body").innerText()).slice(-2_000);
        throw new Error(
          `Workspace wipe acknowledgement failed: ${String(error)}\nResponses: ${JSON.stringify(wipeResponses, null, 2)}\nVisible text: ${visibleText}`,
        );
      }
      await waitForJoined(offline, documentId);
      await expect
        .poll(
          () =>
            offline.evaluate(
              (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
              documentId,
            ),
          { timeout: 60_000 },
        )
        .toBe("joined");
      await expect.poll(() => pendingExists(offline, documentId), { timeout: 30_000 }).toBe(false);
      try {
        await expectVisibleEditorTextContains(offline, baselineText, 60_000);
      } catch (error) {
        const diagnostics = await offline.evaluate(
          (id) => ({
            syncState: window.__refmdGetDocumentSyncState?.(id) ?? null,
            clientLogs: window.__refmdE2EClientLogs ?? [],
          }),
          documentId,
        );
        throw new Error(
          `Post-wipe canonical content was unavailable: ${String(error)}\nDiagnostics: ${JSON.stringify(diagnostics, null, 2)}`,
        );
      }
      expect(await readVisibleEditorText(offline)).not.toContain(wipedOfflineText);

      const saveStartedAt = Date.now();
      await appendTextThroughVisibleEditor(offline, postWipeText);
      await flushDocumentSync(offline, documentId);
      await waitForDurableSaveAcknowledgement(offline, documentId, saveStartedAt);
      await expectVisibleEditorTextContains(owner, postWipeText, 60_000);

      await owner.reload({ waitUntil: "domcontentloaded" });
      await waitForJoined(owner, documentId);
      await expectVisibleEditorTextContains(owner, baselineText, 60_000);
      await expectVisibleEditorTextContains(owner, postWipeText, 60_000);

      await offline.reload({ waitUntil: "domcontentloaded" });
      await waitForJoined(offline, documentId);
      await expectVisibleEditorTextContains(offline, baselineText, 60_000);
      await expectVisibleEditorTextContains(offline, postWipeText, 60_000);
      expect(await readVisibleEditorText(offline)).not.toContain(wipedOfflineText);
    });

    await test.step("keep both revoked targets fail-closed", async () => {
      for (const revokedTarget of [target, secondTarget]) {
        await revokedTarget.goto(documentPath, { waitUntil: "domcontentloaded" });
        await expect(revokedTarget).toHaveURL(/\/auth\/login(?:\?|$)/, { timeout: 60_000 });
        await expect(
          revokedTarget.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]'),
        ).toHaveCount(0);
      }
    });
  } finally {
    await Promise.allSettled([
      secondTargetContext.close(),
      targetContext.close(),
      offlineContext.close(),
      ownerContext.close(),
    ]);
  }
});

async function revokeTargetAndCompleteRotations(
  owner: Page,
  deviceName: string,
  documentPath: string,
  documentId: string,
  kekResponses: Array<{ method: string; path: string; status: number; body: string }>,
): Promise<void> {
  await openSecuritySettings(owner);
  const targetRow = deviceRowByName(owner, deviceName);
  await targetRow.getByTitle("Remove device").click({ timeout: 60_000 });
  await owner.getByText("Lost or compromised").click();
  const kekCompletion = owner.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/encryption\/workspaces\/[^/]+\/rotations\/[^/]+\/complete$/.test(
        new URL(response.url()).pathname,
      ),
    { timeout: 90_000 },
  );
  const workspaceWipeAcknowledgement = owner.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname.endsWith("/kek-rotation/wipe-requirement/acknowledge") &&
      response.status() === 200,
    { timeout: 120_000 },
  );
  const dekPreparation = owner.waitForResponse(
    (response) =>
      response.request().method() === "GET" &&
      new URL(response.url()).pathname.endsWith(
        `/api/encryption/documents/${documentId}/keys/rotation-completion`,
      ),
    { timeout: 120_000 },
  );
  const dekCompletion = owner.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname.endsWith(
        `/api/encryption/documents/${documentId}/keys/rotation-completion`,
      ),
    { timeout: 240_000 },
  );
  const documentWipeAcknowledgement = owner.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname.endsWith(
        `/api/encryption/documents/${documentId}/keys/wipe-requirement/acknowledge`,
      ) &&
      response.status() === 200,
    { timeout: 240_000 },
  );
  await owner.getByRole("button", { name: "Remove Device", exact: true }).click();
  try {
    expect((await kekCompletion).status(), JSON.stringify(kekResponses, null, 2)).toBe(200);
    await workspaceWipeAcknowledgement;
    await owner.goto(documentPath, { waitUntil: "domcontentloaded" });
    await waitForJoined(owner, documentId);
    const preparationResponse = await dekPreparation;
    expect(preparationResponse.status(), await preparationResponse.text()).toBe(200);
    const completionResponse = await dekCompletion;
    expect(completionResponse.status(), await completionResponse.text()).toBe(200);
    await documentWipeAcknowledgement;
  } catch (error) {
    const visibleText = (await owner.locator("body").innerText()).slice(-2_000);
    const clientLogs = await owner.evaluate(() => window.__refmdE2EClientLogs ?? []);
    throw new Error(
      `Rotation failed for ${deviceName}: ${String(error)}\nResponses: ${JSON.stringify(kekResponses, null, 2)}\nClient logs: ${JSON.stringify(clientLogs, null, 2)}\nVisible text: ${visibleText}`,
    );
  }
}

function workspaceWipeResponses(
  responses: Array<{ method: string; path: string; status: number; body: string }>,
  method: string,
  status: number,
) {
  return responses.filter(
    (response) =>
      response.method === method &&
      response.status === status &&
      response.path.includes("/api/encryption/workspaces/") &&
      response.path.includes("/kek-rotation/wipe-requirement"),
  );
}

function documentWipeResponses(
  responses: Array<{ method: string; path: string; status: number; body: string }>,
  documentId: string,
  method: string,
  status: number,
) {
  return responses.filter(
    (response) =>
      response.method === method &&
      response.status === status &&
      response.path.includes(`/api/encryption/documents/${documentId}/keys/wipe-requirement`),
  );
}

async function registerAndApprove(owner: Page, page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });
  await owner.reload({ waitUntil: "domcontentloaded" });
  const approve = owner.getByRole("button", { name: /Emojis Match.*Approve/i });
  await expect(approve).toBeVisible({ timeout: 120_000 });
  await approve.click();
  await expect(page).toHaveURL(/dashboard/, { timeout: 120_000 });
}

async function waitForJoined(page: Page, documentId: string): Promise<void> {
  await expect(
    page.locator('.cm-content, .ProseMirror, [data-testid="markdown-preview"]').first(),
  ).toBeVisible({ timeout: 120_000 });
  await expect
    .poll(
      () =>
        page.evaluate(
          (id) => window.__refmdGetDocumentSyncState?.(id)?.channelState ?? null,
          documentId,
        ),
      { timeout: 120_000 },
    )
    .toBe("joined");
}

async function appendTextThroughVisibleEditor(page: Page, text: string): Promise<void> {
  const editor = visibleEditableEditor(page);
  await expect(editor).toBeVisible({ timeout: 120_000 });
  await editor.click();
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
  await expect(editor).toContainText(text, { timeout: 10_000 });
}

function visibleEditableEditor(page: Page) {
  return page
    .locator(
      '.cm-content[contenteditable="true"]:visible, .ProseMirror[contenteditable="true"]:visible',
    )
    .first();
}

async function expectVisibleEditorTextContains(
  page: Page,
  text: string,
  timeout: number,
): Promise<void> {
  await expect(visibleEditableEditor(page)).toContainText(text, { timeout });
}

async function readVisibleEditorText(page: Page): Promise<string> {
  return visibleEditableEditor(page).innerText();
}

async function waitForDurableSaveAcknowledgement(
  page: Page,
  documentId: string,
  saveStartedAt: number,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          ({ id, startedAt }) => {
            const state = window.__refmdGetDocumentSyncState?.(id);
            if (!state) return false;
            const events = state.recentSaveEvents as Array<{ event?: string; at?: number }>;
            return (
              events.some(
                (event) => event.event === "update_saved_received" && (event.at ?? 0) >= startedAt,
              ) &&
              !state.pendingSave &&
              !state.pendingUpdate &&
              !state.pendingUpdateBytes &&
              !state.pendingUpdateEnvelope &&
              !state.sending &&
              !state.unsavedCanonicalText
            );
          },
          { id: documentId, startedAt: saveStartedAt },
        ),
      { timeout: 60_000 },
    )
    .toBe(true);
}

async function flushDocumentSync(page: Page, documentId: string): Promise<void> {
  await page.evaluate(async (id) => {
    if (!window.__refmdFlushDocumentSync) throw new Error("document_sync_flush_unavailable");
    await window.__refmdFlushDocumentSync(id);
  }, documentId);
}

async function pendingExists(page: Page, documentId: string): Promise<boolean> {
  return page.evaluate(
    ({ databaseName, id, storeName }) =>
      new Promise<boolean>((resolve, reject) => {
        const request = indexedDB.open(databaseName);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(storeName)) {
            db.close();
            resolve(false);
            return;
          }
          const transaction = db.transaction(storeName, "readonly");
          const get = transaction.objectStore(storeName).get(id);
          get.onerror = () => reject(get.error);
          get.onsuccess = () => resolve(get.result !== undefined);
          transaction.oncomplete = () => db.close();
        };
      }),
    { databaseName: "refmd-offline", id: documentId, storeName: "pending-changes" },
  );
}
