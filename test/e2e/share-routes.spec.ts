import { test, expect, type BrowserContext, type Page } from "@playwright/test";
import {
  createDocument,
  openContextMenu,
  openDocument,
  registerAccount,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

let sharedContext: BrowserContext;
let dashboardPage: Page;
let sharePage: Page;
let documentId: string;
let shareSlug: string;
let documentToken: string;

function shareDocumentRouteRegex(token: string): RegExp {
  return new RegExp(`/share/d/${token}$`);
}

async function currentDocumentId(page: Page): Promise<string> {
  const pathname = new URL(page.url()).pathname;
  const match = pathname.match(/^\/document\/([^/]+)$/);
  if (!match) {
    throw new Error(`current path is not a document route: ${pathname}`);
  }
  return match[1];
}

async function createShareLinkFromUi(
  page: Page,
  title: string,
): Promise<string> {
  const menu = await openContextMenu(page, title);
  await menu.getByRole("menuitem", { name: "Share" }).click();

  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByText("Share Access")).toBeVisible({
    timeout: 10_000,
  });
  await dialog.getByRole("button", { name: "Create new link" }).click();
  await dialog.getByRole("button", { name: "Create Link" }).click();

  const input = dialog.locator("input[readonly]");
  await expect(input).toHaveValue(/\/share\/[^/]+$/, { timeout: 60_000 });
  const link = await input.inputValue();
  await page.keyboard.press("Escape");

  const slug = new URL(link).pathname.match(/^\/share\/([^/]+)$/)?.[1];
  if (!slug)
    throw new Error(`share link did not include a share slug: ${link}`);
  return slug;
}

async function countSpinnerVisibilityFlips(page: Page, durationMs: number): Promise<number> {
  return page.evaluate(async (duration) => {
    const hasSpinner = () => document.querySelectorAll('[data-slot="spinner"]').length > 0;
    let previous = hasSpinner();
    let flips = 0;
    const deadline = performance.now() + duration;

    while (performance.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const current = hasSpinner();
      if (current !== previous) {
        flips += 1;
        previous = current;
      }
    }

    return flips;
  }, durationMs);
}

test.describe.serial("Share Route Session Coexistence", () => {
  test.beforeAll(async ({ browser }) => {
    sharedContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    dashboardPage = await sharedContext.newPage();
    sharePage = await sharedContext.newPage();
  });

  test.afterAll(async () => {
    await sharedContext.close();
  });

  test("setup: register account, create document, and create a view share", async () => {
    test.setTimeout(180_000);

    await registerAccount(dashboardPage);
    await createDocument(dashboardPage, "Shared Route Doc");
    await openDocument(dashboardPage, "Shared Route Doc");

    documentId = await currentDocumentId(dashboardPage);
    shareSlug = await createShareLinkFromUi(dashboardPage, "Shared Route Doc");

    expect(documentId).toBeTruthy();
    expect(shareSlug).toBeTruthy();
  });

  test("landing route redirects to canonical route with share-scoped requests and keeps both cookies", async () => {
    test.setTimeout(60_000);

    const landingHeaders: Array<string | undefined> = [];
    const canonicalRequests: Array<{ path: string; scope: string | undefined }> = [];

    sharePage.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path === `/api/shares/${shareSlug}`) {
        landingHeaders.push(request.headers()["x-refmd-session-scope"]);
      }
      if (path.startsWith("/api/shares/d/")) {
        canonicalRequests.push({
          path,
          scope: request.headers()["x-refmd-session-scope"],
        });
      }
    });

    await sharePage.goto(`/share/${shareSlug}`, {
      waitUntil: "domcontentloaded",
    });

    await expect(sharePage).toHaveURL(/\/share\/d\/[^/]+$/, {
      timeout: 30_000,
    });
    documentToken = new URL(sharePage.url()).pathname.split("/").at(-1) ?? "";
    expect(documentToken).toBeTruthy();
    await expect(
      sharePage.locator("aside").getByText("Shared Route Doc", { exact: true }),
    ).toBeVisible({
      timeout: 30_000,
    });
    await expect
      .poll(() => sharePage.locator("[data-panel-id]").count(), {
        timeout: 30_000,
        message: "shared document did not open in the mosaic workspace",
      })
      .toBeGreaterThan(0);

    await expect
      .poll(() => landingHeaders.length, {
        timeout: 10_000,
        message: "share landing request was not observed",
      })
      .toBeGreaterThan(0);

    await expect
      .poll(() => canonicalRequests.some((entry) => entry.path === `/api/shares/d/${documentToken}`), {
        timeout: 10_000,
        message: "share canonical request was not observed",
      })
      .toBe(true);

    expect(landingHeaders).toContain("share");
    expect(
      canonicalRequests
        .filter((entry) => entry.path === `/api/shares/d/${documentToken}`)
        .map((entry) => entry.scope),
    ).toContain("share");

    const cookies = await sharedContext.cookies();
    expect(cookies.some((cookie) => cookie.name === "_refmd_session")).toBe(
      true,
    );
    expect(
      cookies.some((cookie) => cookie.name === "_refmd_share_session"),
    ).toBe(true);

    await dashboardPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(dashboardPage);
  });

  test("canonical share route survives reload with share-scoped bootstrap", async () => {
    test.setTimeout(60_000);

    const canonicalHeaders: Array<string | undefined> = [];

    sharePage.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path === `/api/shares/d/${documentToken}`) {
        canonicalHeaders.push(request.headers()["x-refmd-session-scope"]);
      }
    });

    await sharePage.reload({ waitUntil: "domcontentloaded" });

    await expect(sharePage).toHaveURL(shareDocumentRouteRegex(documentToken), {
      timeout: 30_000,
    });

    await expect
      .poll(() => canonicalHeaders.length, {
        timeout: 10_000,
        message: "share canonical request on reload was not observed",
      })
      .toBeGreaterThan(0);

    expect(canonicalHeaders).toContain("share");
  });

  test("anonymous canonical share route uses share-scoped auth transport", async ({ browser }) => {
    test.setTimeout(60_000);

    const anonymousContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    const anonymousPage = await anonymousContext.newPage();
    const authMeRequests: string[] = [];
    const popChallengeScopes: Array<string | undefined> = [];
    const wsTokenScopes: Array<string | undefined> = [];

    anonymousPage.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path === "/api/auth/me") authMeRequests.push(path);
      if (path === "/api/auth/pop-challenge") {
        popChallengeScopes.push(request.headers()["x-refmd-session-scope"]);
      }
      if (path === "/api/auth/ws-token") {
        wsTokenScopes.push(request.headers()["x-refmd-session-scope"]);
      }
    });

    try {
      await anonymousPage.goto(`/share/d/${documentToken}`, {
        waitUntil: "domcontentloaded",
      });

      await expect(anonymousPage).toHaveURL(shareDocumentRouteRegex(documentToken), {
        timeout: 30_000,
      });
      await expect(
        anonymousPage.locator("aside").getByText("Shared Route Doc", { exact: true }),
      ).toBeVisible({
        timeout: 30_000,
      });
      await expect
        .poll(() => anonymousPage.locator("[data-panel-id]").count(), {
          timeout: 30_000,
          message: "anonymous shared document did not open in the mosaic workspace",
        })
        .toBeGreaterThan(0);

      const spinnerFlips = await countSpinnerVisibilityFlips(anonymousPage, 3_000);
      expect(spinnerFlips).toBeLessThanOrEqual(1);

      await anonymousPage.waitForTimeout(3_000);
      expect(authMeRequests.length).toBeLessThanOrEqual(1);
      expect(popChallengeScopes).not.toContain(undefined);
      expect(popChallengeScopes).not.toContain("user");
      expect(wsTokenScopes).not.toContain(undefined);
      expect(wsTokenScopes).not.toContain("user");
    } finally {
      await anonymousContext.close();
    }
  });

  test("canonical direct access without a share session bootstraps and recovers", async () => {
    test.setTimeout(60_000);

    await sharePage.close();
    const reentryPage = await sharedContext.newPage();
    const bootstrapPaths: string[] = [];
    const canonicalPaths: string[] = [];

    reentryPage.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path === `/api/shares/${shareSlug}/bootstrap`) {
        bootstrapPaths.push(path);
      }
      if (path === `/api/shares/d/${documentToken}`) {
        canonicalPaths.push(path);
      }
    });

    await sharedContext.addCookies([
      {
        name: "_refmd_share_session",
        value: "",
        domain: "localhost",
        path: "/api",
        expires: 0,
        httpOnly: true,
        sameSite: "Lax",
      },
    ]);

    await reentryPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await reentryPage.evaluate(async () => {
      localStorage.removeItem("refmd-share-participant-session");
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase("refmd-share-sessions");
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
        request.onsuccess = () => resolve();
      });
    });

    await reentryPage.goto(`/share/d/${documentToken}`, {
      waitUntil: "domcontentloaded",
    });

    await expect(reentryPage).toHaveURL(
      shareDocumentRouteRegex(documentToken),
      {
        timeout: 30_000,
      },
    );

    await expect
      .poll(() => canonicalPaths.length, {
        timeout: 10_000,
        message: "canonical direct-access request was not observed",
      })
      .toBeGreaterThan(0);

    await expect
      .poll(() => bootstrapPaths.length, {
        timeout: 10_000,
        message: "canonical re-entry bootstrap request was not observed",
      })
      .toBeGreaterThan(0);

    await reentryPage.close();
  });

  test("protected share landing prompts for a password and submits the unlock challenge", async () => {
    test.setTimeout(60_000);

    const protectedShareSlug = "mock-protected-share";
    const protectedDocumentToken = "mock-protected-doc";
    const challenge = Buffer.alloc(32, 7).toString("base64url");
    const salt = Buffer.alloc(16, 3).toString("base64url");
    const challengeBodies: Array<Record<string, unknown>> = [];
    const protectedPage = await sharedContext.newPage();

    await protectedPage.route(
      `**/api/shares/${protectedShareSlug}`,
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            share: {
              id: "00000000-0000-0000-0000-000000000000",
              document_id: "00000000-0000-0000-0000-000000000001",
              scope: "document",
              permission: "view",
              password_protected: true,
            },
            root: {
              kind: "document",
              document_token: protectedDocumentToken,
            },
          }),
        });
      },
    );

    await protectedPage.route(
      `**/api/shares/${protectedShareSlug}/challenge`,
      async (route) => {
        if (route.request().method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              challenge,
              salt,
              kdf_params: {
                algorithm: "argon2id",
                memory: 65536,
                iterations: 3,
                parallelism: 4,
                hash_length: 32,
              },
            }),
          });
          return;
        }

        challengeBodies.push(
          (route.request().postDataJSON() ?? {}) as Record<string, unknown>,
        );
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            root: {
              kind: "document",
              document_token: protectedDocumentToken,
            },
            participant: {
              principal_id: "00000000-0000-0000-0000-000000000010",
              device_id: "00000000-0000-0000-0000-000000000011",
              grant: "view",
            },
          }),
        });
      },
    );

    await protectedPage.goto(`/share/${protectedShareSlug}`, {
      waitUntil: "domcontentloaded",
    });

    await expect(
      protectedPage.getByRole("heading", {
        name: "Enter password to continue",
      }),
    ).toBeVisible();

    await protectedPage
      .getByLabel("Password")
      .fill("correct horse battery staple");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect
      .poll(() => challengeBodies.length, {
        timeout: 15_000,
        message: "challenge response request was not observed",
      })
      .toBe(1);

    expect(challengeBodies[0]?.display_name).toBe("Guest");
    expect(typeof challengeBodies[0]?.response).toBe("string");
    expect(challengeBodies[0]?.response).not.toBe("");

    await expect(protectedPage).toHaveURL(
      shareDocumentRouteRegex(protectedDocumentToken),
      {
        timeout: 30_000,
      },
    );

    await protectedPage.close();
  });

  test("protected share landing stays on the password prompt after an unlock failure and allows retry", async () => {
    test.setTimeout(60_000);

    const protectedShareSlug = "mock-protected-share-retry";
    const protectedDocumentToken = "mock-protected-doc-retry";
    const challenge = Buffer.alloc(32, 9).toString("base64url");
    const salt = Buffer.alloc(16, 5).toString("base64url");
    const challengeBodies: Array<Record<string, unknown>> = [];
    const protectedPage = await sharedContext.newPage();
    let respondAttempts = 0;

    await protectedPage.route(
      `**/api/shares/${protectedShareSlug}`,
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            share: {
              id: "00000000-0000-0000-0000-000000000100",
              document_id: "00000000-0000-0000-0000-000000000101",
              scope: "document",
              permission: "view",
              password_protected: true,
            },
            root: {
              kind: "document",
              document_token: protectedDocumentToken,
            },
          }),
        });
      },
    );

    await protectedPage.route(
      `**/api/shares/${protectedShareSlug}/challenge`,
      async (route) => {
        if (route.request().method() === "GET") {
          await route.fulfill({
            status: 200,
            headers: {
              "cache-control": "no-store",
            },
            contentType: "application/json",
            body: JSON.stringify({
              challenge,
              salt,
              kdf_params: {
                algorithm: "argon2id",
                memory: 65536,
                iterations: 3,
                parallelism: 4,
                hash_length: 32,
              },
            }),
          });
          return;
        }

        challengeBodies.push(
          (route.request().postDataJSON() ?? {}) as Record<string, unknown>,
        );
        respondAttempts += 1;

        if (respondAttempts === 1) {
          await route.fulfill({
            status: 404,
            contentType: "application/json",
            body: JSON.stringify({ error: "not_found" }),
          });
          return;
        }

        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            root: {
              kind: "document",
              document_token: protectedDocumentToken,
            },
            participant: {
              principal_id: "00000000-0000-0000-0000-000000000110",
              device_id: "00000000-0000-0000-0000-000000000111",
              grant: "view",
            },
          }),
        });
      },
    );

    await protectedPage.goto(`/share/${protectedShareSlug}`, {
      waitUntil: "domcontentloaded",
    });

    await protectedPage.getByLabel("Password").fill("wrong password");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect(
      protectedPage.getByText("Share not found or password is invalid."),
    ).toBeVisible();
    await expect(protectedPage).toHaveURL(
      new RegExp(`/share/${protectedShareSlug}$`),
    );

    await protectedPage
      .getByLabel("Password")
      .fill("correct horse battery staple");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect
      .poll(() => challengeBodies.length, {
        timeout: 15_000,
        message: "challenge retry request was not observed",
      })
      .toBe(2);

    await expect(protectedPage).toHaveURL(
      shareDocumentRouteRegex(protectedDocumentToken),
      {
        timeout: 30_000,
      },
    );

    await protectedPage.close();
  });
});
