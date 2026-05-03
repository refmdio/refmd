import { expect, test, type WebSocketRoute } from "@playwright/test";
import { createDocument, newE2EContext, openDocument, readEditorText, registerAccount } from "./helpers";

test("workspace document buffers edits while the websocket is disconnected", async ({ browser }) => {
  test.setTimeout(180_000);

  const context = await newE2EContext(browser, { bypassCSP: true });
  const sockets: WebSocketRoute[] = [];
  let allowSocket = true;

  await context.routeWebSocket((url) => url.pathname.startsWith("/api/socket"), (socket) => {
    sockets.push(socket);
    if (!allowSocket) {
      void socket.close();
      return;
    }
    socket.connectToServer();
  });

  const page = await context.newPage();
  try {
    await registerAccount(page);
    await createDocument(page, "WebSocket Disconnect Guard Doc");
    await openDocument(page, "WebSocket Disconnect Guard Doc");

    const editor = page.locator(".cm-content");
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await expect.poll(() => sockets.length, { timeout: 30_000 }).toBeGreaterThan(0);

    await editor.click();
    await page.keyboard.insertText("Connected baseline");
    await page.waitForTimeout(5_000);
    await expect.poll(() => readEditorText(page), { timeout: 10_000 }).toContain(
      "Connected baseline",
    );

    allowSocket = false;
    await Promise.all(sockets.map((socket) => socket.close({ code: 1001 })));
    await expect(page.getByText("Offline")).toBeVisible({ timeout: 30_000 });

    await editor.click();
    await page.keyboard.press("End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText("Buffered while websocket is disconnected");
    await page.waitForTimeout(1_000);

    await expect.poll(() => readEditorText(page), { timeout: 10_000 }).toContain(
      "Buffered while websocket is disconnected",
    );

    allowSocket = true;
    await expect(page.getByText("Offline")).toBeHidden({ timeout: 30_000 });
    await expect.poll(() => readEditorText(page), { timeout: 10_000 }).toContain(
      "Buffered while websocket is disconnected",
    );
  } finally {
    await context.close();
  }
});

test("hard-reloaded document stays read-only before websocket re-baseline", async ({ browser }) => {
  test.setTimeout(180_000);

  const context = await newE2EContext(browser, { bypassCSP: true });
  const sockets: WebSocketRoute[] = [];
  let allowSocket = true;

  await context.routeWebSocket((url) => url.pathname.startsWith("/api/socket"), (socket) => {
    sockets.push(socket);
    if (!allowSocket) {
      void socket.close({ code: 1001 });
      return;
    }
    socket.connectToServer();
  });

  const page = await context.newPage();
  try {
    await registerAccount(page);
    await createDocument(page, "Hard Reload WebSocket Guard Doc");
    await openDocument(page, "Hard Reload WebSocket Guard Doc");

    const editor = page.locator(".cm-content");
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.click();
    await page.keyboard.insertText("Reload baseline");
    await expect.poll(() => readEditorText(page), { timeout: 10_000 }).toContain("Reload baseline");

    allowSocket = false;
    await Promise.all(sockets.map((socket) => socket.close({ code: 1001 })));
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Offline")).toBeVisible({ timeout: 30_000 });

    await editor.click();
    await page.keyboard.press("End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText("Should not be accepted before websocket rebaseline");
    await page.waitForTimeout(1_000);

    await expect(await readEditorText(page)).not.toContain(
      "Should not be accepted before websocket rebaseline",
    );

    allowSocket = true;
    await expect(page.getByText("Offline")).toBeHidden({ timeout: 30_000 });
  } finally {
    await context.close();
  }
});
