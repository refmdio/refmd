import { test, expect, chromium } from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { registerAccount, createDocument } from "./helpers";

const baseURL = process.env.BASE_URL || "http://localhost:5173";
const requiresStaticServer = !baseURL.includes(":5173");

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
    await page.waitForTimeout(1_000);

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

test("service worker serves app shell after browser restart while fully offline", async () => {
  test.skip(!requiresStaticServer, "Requires Phoenix/static asset server, not Vite dev server");
  test.setTimeout(240_000);

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "refmd-sw-e2e-"));
  let context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | null = null;

  try {
    context = await chromium.launchPersistentContext(userDataDir, {
      baseURL,
      acceptDownloads: true,
      headless: true,
      args: ["--disable-web-security"],
    });

    let page = context.pages()[0] ?? (await context.newPage());

    await registerAccount(page);
    await createDocument(page, "SW Cold Start Doc");
    await openDocument(page, "SW Cold Start Doc");

    const editor = page.locator(".cm-content");
    await editor.click();
    await page.keyboard.type("Cold start offline content");
    await page.waitForTimeout(5_000);

    await waitForServiceWorker(page);

    const cacheState = await page.evaluate(async () => {
      const cache = await caches.open("app-shell-v1");
      const keys = await cache.keys();
      return {
        count: keys.length,
        hasIndex: keys.some((req) => new URL(req.url).pathname === "/index.html"),
      };
    });
    expect(cacheState.hasIndex).toBe(true);
    expect(cacheState.count).toBeGreaterThan(1);

    await context.close();
    context = await chromium.launchPersistentContext(userDataDir, {
      baseURL,
      acceptDownloads: true,
      headless: true,
      args: ["--disable-web-security"],
    });

    await context.setOffline(true);
    page = context.pages()[0] ?? (await context.newPage());

    await page.goto("/dashboard", { waitUntil: "domcontentloaded", timeout: 60_000 });

    const docButton = page.getByRole("button", { name: "SW Cold Start Doc" });

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
    await expect(page.locator(".cm-content")).toContainText("Cold start offline content", {
      timeout: 60_000,
    });

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
