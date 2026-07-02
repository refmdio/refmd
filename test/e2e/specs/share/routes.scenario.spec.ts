import {
  test,
  expect,
  type Browser,
  type BrowserContext,
  type Page,
  type WebSocketRoute,
} from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openContextMenu,
  openDocument,
} from "../../support/documents";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

const MOCK_WPB_HASH = Buffer.alloc(32, 0).toString("base64url");
const MOCK_PROTECTED_CAPABILITY = Buffer.alloc(32, 1).toString("base64url");
const MOCK_RETRY_PROTECTED_CAPABILITY = Buffer.alloc(32, 2).toString("base64url");
const MOCK_PASSWORD_CAPABILITY_SECRET_COMMITMENT = Buffer.alloc(32, 7).toString("base64url");
const MOCK_SHARE_BOOTSTRAP_FIELDS = {
  share_id: "00000000-0000-4000-8000-000000000000",
  scope_kind: "document",
  scope_id: "00000000-0000-4000-8000-000000000001",
  created_event_hash: Buffer.alloc(32, 3).toString("base64url"),
  latest_bootstrap_event_hash: Buffer.alloc(32, 4).toString("base64url"),
  capability_context_hash: Buffer.alloc(32, 5).toString("base64url"),
  share_capability_secret_commitment: Buffer.alloc(32, 6).toString("base64url"),
} as const;

let sharedContext: BrowserContext;
let dashboardPage: Page;
let sharePage: Page;
let documentId: string;
let shareSlug: string;
let shareCap: string;
let shareWpb: string;
let documentToken: string;

function shareDocumentRouteRegex(token: string): RegExp {
  return new RegExp(`/share/d/${token}(?:#s=[A-Za-z0-9_-]{22})?$`);
}

async function expectNoVisibleShareRouteError(page: Page): Promise<void> {
  const bodyText = await page.locator("body").innerText({ timeout: 10_000 });
  expect(bodyText).not.toContain("Share document not found.");
  expect(bodyText).not.toContain("Share not found.");
  expect(bodyText).not.toContain("Invalid share document route.");
  expect(bodyText).not.toContain("Invalid share link.");
}

async function expectInvalidShareLinkWithoutDocumentNotFound(page: Page): Promise<void> {
  await expect(page.getByText("Invalid share link.")).toBeVisible({ timeout: 30_000 });
  const bodyText = await page.locator("body").innerText({ timeout: 10_000 });
  expect(bodyText).not.toContain("Share document not found.");
  expect(bodyText).not.toContain("Share not found.");
}

async function expectSharedDocumentWorkspaceOpen(
  page: Page,
  title: string,
  message: string,
): Promise<void> {
  await expectNoVisibleShareRouteError(page);
  await expect
    .poll(() => page.locator("body").innerText(), {
      timeout: 30_000,
      message: `${message}: shared title was not visible`,
    })
    .toContain(title);
  await expect
    .poll(() => page.locator("[data-panel-id], .cm-content, .ProseMirror").count(), {
      timeout: 30_000,
      message,
    })
    .toBeGreaterThan(0);
  await expectNoVisibleShareRouteError(page);
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
): Promise<{ slug: string; cap: string; wpb: string }> {
  const menu = await openContextMenu(page, title);
  await menu.getByRole("menuitem", { name: "Share" }).click();

  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByText("Share Access")).toBeVisible({
    timeout: 10_000,
  });
  await dialog.getByRole("button", { name: "Create new link" }).click();
  const createResponsePromise = page.waitForResponse(
    (response) => {
      const url = new URL(response.url());
      return (
        response.request().method() === "POST" &&
        /^\/api\/documents\/[^/]+\/shares$/.test(url.pathname)
      );
    },
    { timeout: 60_000 },
  );
  await dialog.getByRole("button", { name: "Create Link" }).click();
  const createResponse = await createResponsePromise;
  if (!createResponse.ok()) {
    throw new Error(
      `share create failed: ${createResponse.status()} ${await createResponse.text()}`,
    );
  }

  const input = dialog.locator("input[readonly]");
  await expect(input).toHaveValue(/\/share\/[^/#]+#cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}$/, {
    timeout: 60_000,
  });
  const link = await input.inputValue();
  await page.keyboard.press("Escape");

  const url = new URL(link);
  const slug = url.pathname.match(/^\/share\/([^/]+)$/)?.[1];
  if (!slug) throw new Error(`share link did not include a share slug: ${link}`);
  const fragment = new URLSearchParams(url.hash.slice(1));
  const cap = fragment.get("cap");
  const wpb = fragment.get("wpb");
  if (!cap || !/^[A-Za-z0-9_-]{43}$/.test(cap)) {
    throw new Error(`share link did not include a capability secret: ${link}`);
  }
  if (!wpb) throw new Error(`share link did not include a wpb hash: ${link}`);
  return { slug, cap, wpb };
}

async function resolveShareDocumentToken(
  browser: Browser,
  slug: string,
  cap: string,
  wpb: string,
): Promise<string> {
  const tokenContext = await newE2EContext(browser, {
    bypassCSP: true,
    acceptDownloads: true,
  });
  const tokenPage = await tokenContext.newPage();

  try {
    await tokenPage.goto(`/share/${slug}#cap=${cap}&wpb=${wpb}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(tokenPage).toHaveURL(/\/share\/d\/[^/#]+#s=[A-Za-z0-9_-]{22}$/, {
      timeout: 30_000,
    });

    const token = new URL(tokenPage.url()).pathname.split("/").at(-1) ?? "";
    if (!token) {
      throw new Error(`share landing did not resolve a document token: ${tokenPage.url()}`);
    }
    return token;
  } finally {
    await tokenContext.close();
  }
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

function isUserLifecycleRequestPath(path: string): boolean {
  return (
    path === "/api/auth/me" ||
    path === "/api/devices" ||
    path.startsWith("/api/devices/registrations") ||
    path.startsWith("/api/security/notifications")
  );
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

  test.beforeAll(async ({ browser }, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);

    await registerAccount(dashboardPage);
    await createDocument(dashboardPage, "Shared Route Doc");
    await openDocument(dashboardPage, "Shared Route Doc");

    documentId = await currentDocumentId(dashboardPage);
    const shareLink = await createShareLinkFromUi(dashboardPage, "Shared Route Doc");
    shareSlug = shareLink.slug;
    shareCap = shareLink.cap;
    shareWpb = shareLink.wpb;
    documentToken = await resolveShareDocumentToken(browser, shareSlug, shareCap, shareWpb);

    expect(documentId).toBeTruthy();
    expect(shareSlug).toBeTruthy();
    expect(shareCap).toBeTruthy();
    expect(shareWpb).toBeTruthy();
    expect(documentToken).toBeTruthy();
  });

  test("share routes preserve scoped sessions and protected unlock flows", async ({ browser }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("landing route redirects to canonical route with share-scoped requests and keeps both cookies", async () => {
      const landingHeaders: Array<string | undefined> = [];
      const landingBootstrapHeaders: Array<string | undefined> = [];
      const canonicalRequests: Array<{ path: string; scope: string | undefined }> = [];

      sharePage.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (path === `/api/shares/${shareSlug}`) {
          landingHeaders.push(request.headers()["x-refmd-session-scope"]);
        }
        if (path === `/api/shares/${shareSlug}/bootstrap`) {
          landingBootstrapHeaders.push(request.headers()["x-refmd-session-scope"]);
        }
        if (path.startsWith("/api/shares/d/")) {
          canonicalRequests.push({
            path,
            scope: request.headers()["x-refmd-session-scope"],
          });
        }
      });

      await sharePage.goto(`/share/${shareSlug}#cap=${shareCap}&wpb=${shareWpb}`, {
        waitUntil: "domcontentloaded",
      });

      await expect(sharePage).toHaveURL(/\/share\/d\/[^/#]+#s=[A-Za-z0-9_-]{22}$/, {
        timeout: 30_000,
      });
      const canonicalUrl = new URL(sharePage.url());
      expect(canonicalUrl.hash).toBe(`#s=${shareSlug}`);
      expect(canonicalUrl.hash).not.toContain("cap=");
      expect(canonicalUrl.hash).not.toContain("wpb=");
      const redirectedDocumentToken = new URL(sharePage.url()).pathname.split("/").at(-1) ?? "";
      expect(redirectedDocumentToken).toBe(documentToken);
      await expectSharedDocumentWorkspaceOpen(
        sharePage,
        "Shared Route Doc",
        "shared document did not open in the mosaic workspace",
      );

      await expect
        .poll(() => landingHeaders.length, {
          timeout: 10_000,
          message: "share landing request was not observed",
        })
        .toBeGreaterThan(0);

      await expect
        .poll(
          () =>
            landingBootstrapHeaders.length > 0 ||
            canonicalRequests.some((entry) => entry.path === `/api/shares/d/${documentToken}`),
          {
            timeout: 10_000,
            message: "share bootstrap or canonical request was not observed",
          },
        )
        .toBe(true);

      const routeScopes = [
        ...landingHeaders,
        ...landingBootstrapHeaders,
        ...canonicalRequests
          .filter((entry) => entry.path === `/api/shares/d/${documentToken}`)
          .map((entry) => entry.scope),
      ];
      expect(routeScopes).toContain("share");
      expect(routeScopes).not.toContain("user");
      expect(routeScopes).not.toContain(undefined);

      const cookies = await sharedContext.cookies();
      expect(cookies.some((cookie) => cookie.name === "_refmd_session")).toBe(true);
      expect(cookies.some((cookie) => cookie.name === "_refmd_share_session")).toBe(true);

      await dashboardPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await waitForWorkspaceReady(dashboardPage);
    });

    await test.step("canonical share route survives reload with share-scoped bootstrap", async () => {
      const canonicalHeaders: Array<string | undefined> = [];

      sharePage.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (path === `/api/shares/d/${documentToken}`) {
          canonicalHeaders.push(request.headers()["x-refmd-session-scope"]);
        }
      });

      await sharePage.goto(`/share/d/${documentToken}#s=${shareSlug}`, {
        waitUntil: "domcontentloaded",
      });
      await expect(sharePage).toHaveURL(shareDocumentRouteRegex(documentToken), {
        timeout: 30_000,
      });
      await expectSharedDocumentWorkspaceOpen(
        sharePage,
        "Shared Route Doc",
        "canonical share document route did not open before reload",
      );

      await sharePage.reload({ waitUntil: "domcontentloaded" });
      await expect(sharePage).toHaveURL(shareDocumentRouteRegex(documentToken), {
        timeout: 30_000,
      });
      await expectSharedDocumentWorkspaceOpen(
        sharePage,
        "Shared Route Doc",
        "canonical share document route did not reopen after reload",
      );

      await sharePage.evaluate((token) => {
        window.history.replaceState({}, "", `/share/d/${token}`);
      }, documentToken);
      await sharePage.reload({ waitUntil: "domcontentloaded" });

      await expect(sharePage).toHaveURL(shareDocumentRouteRegex(documentToken), {
        timeout: 30_000,
      });
      await expectSharedDocumentWorkspaceOpen(
        sharePage,
        "Shared Route Doc",
        "hash-stripped canonical share document reload did not recover from stored session",
      );

      await expect
        .poll(() => canonicalHeaders.length, {
          timeout: 10_000,
          message: "share canonical request on reload was not observed",
        })
        .toBeGreaterThan(0);

      expect(canonicalHeaders).toContain("share");
    });

    await test.step("logged-in direct share access does not start user session lifecycle", async () => {
      const loggedInSharePage = await sharedContext.newPage();
      const userLifecycleRequests: string[] = [];
      const userScopedPopChallenges: Array<string | undefined> = [];

      loggedInSharePage.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (isUserLifecycleRequestPath(path)) {
          userLifecycleRequests.push(path);
        }
        if (path === "/api/auth/pop-challenge") {
          const scope = request.headers()["x-refmd-session-scope"];
          if (scope !== "share") userScopedPopChallenges.push(scope);
        }
      });

      try {
        await loggedInSharePage.goto(`/share/d/${documentToken}#s=${shareSlug}`, {
          waitUntil: "domcontentloaded",
        });
        await expect(loggedInSharePage).toHaveURL(shareDocumentRouteRegex(documentToken), {
          timeout: 30_000,
        });
        await expectSharedDocumentWorkspaceOpen(
          loggedInSharePage,
          "Shared Route Doc",
          "logged-in share direct route did not remain on the share workspace",
        );

        await loggedInSharePage.waitForTimeout(E2E_DELAYS.routeSettle);
        expect(userLifecycleRequests).toEqual([]);
        expect(userScopedPopChallenges).toEqual([]);
      } finally {
        await loggedInSharePage.close();
      }
    });

    await test.step("anonymous canonical share route uses share-scoped auth transport", async () => {
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
        await anonymousPage.goto(
          `/share/d/${documentToken}#cap=${shareCap}&wpb=${shareWpb}&s=${shareSlug}`,
          {
            waitUntil: "domcontentloaded",
          },
        );

        await expect(anonymousPage).toHaveURL(shareDocumentRouteRegex(documentToken), {
          timeout: 30_000,
        });
        await expectSharedDocumentWorkspaceOpen(
          anonymousPage,
          "Shared Route Doc",
          "anonymous shared document did not open in the mosaic workspace",
        );

        const spinnerFlips = await countSpinnerVisibilityFlips(anonymousPage, 3_000);
        expect(spinnerFlips).toBeLessThanOrEqual(1);

        await anonymousPage.waitForTimeout(E2E_DELAYS.routeSettle);
        expect(authMeRequests.length).toBeLessThanOrEqual(2);
        expect(popChallengeScopes).not.toContain(undefined);
        expect(popChallengeScopes).not.toContain("user");
        expect(wsTokenScopes).not.toContain(undefined);
        expect(wsTokenScopes).not.toContain("user");
      } finally {
        await anonymousContext.close();
      }
    });

    await test.step("canonical direct access without a share session bootstraps and recovers", async () => {
      const reentryContext = await newE2EContext(browser, {
        bypassCSP: true,
        acceptDownloads: true,
      });
      const reentryPage = await reentryContext.newPage();
      const landingBootstrapPaths: string[] = [];
      const documentBootstrapPaths: string[] = [];
      const canonicalPaths: string[] = [];

      reentryPage.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if (path === `/api/shares/${shareSlug}/bootstrap`) {
          landingBootstrapPaths.push(path);
        }
        if (path === `/api/shares/d/${documentToken}/bootstrap`) {
          documentBootstrapPaths.push(path);
        }
        if (path === `/api/shares/d/${documentToken}`) {
          canonicalPaths.push(path);
        }
      });

      try {
        await reentryPage.goto(
          `/share/d/${documentToken}#cap=${shareCap}&wpb=${shareWpb}&s=${shareSlug}`,
          {
            waitUntil: "domcontentloaded",
          },
        );

        await expect(reentryPage).toHaveURL(shareDocumentRouteRegex(documentToken), {
          timeout: 30_000,
        });

        await expect
          .poll(() => canonicalPaths.length, {
            timeout: 10_000,
            message: "canonical direct-access request was not observed",
          })
          .toBeGreaterThan(0);

        await expect
          .poll(() => landingBootstrapPaths.length + documentBootstrapPaths.length, {
            timeout: 10_000,
            message: "canonical re-entry bootstrap request was not observed",
          })
          .toBeGreaterThan(0);

        await expectSharedDocumentWorkspaceOpen(
          reentryPage,
          "Shared Route Doc",
          "canonical re-entry did not open the shared document",
        );
      } finally {
        await reentryContext.close();
      }
    });

    await test.step("canonical direct access renders workspace chrome while document sync is delayed", async () => {
      const delayedContext = await newE2EContext(browser, {
        bypassCSP: true,
        acceptDownloads: true,
      });
      const delayedSockets: WebSocketRoute[] = [];
      const delayedPage = await delayedContext.newPage();
      await delayedPage.routeWebSocket(
        (url) => url.pathname.startsWith("/api/socket"),
        (socket) => {
          delayedSockets.push(socket);
        },
      );

      try {
        await delayedPage.goto(
          `/share/d/${documentToken}#cap=${shareCap}&wpb=${shareWpb}&s=${shareSlug}`,
          {
            waitUntil: "domcontentloaded",
          },
        );

        await expect(delayedPage).toHaveURL(shareDocumentRouteRegex(documentToken), {
          timeout: 30_000,
        });
        await expect(delayedPage.getByText("Shared", { exact: true })).toBeVisible({
          timeout: 5_000,
        });
        await expect(delayedPage.getByText("Shared Route Doc", { exact: true }).first()).toBeVisible(
          {
            timeout: 5_000,
          },
        );
        await expectNoVisibleShareRouteError(delayedPage);
        await expect
          .poll(() => delayedSockets.length, {
            timeout: 15_000,
            message: "delayed share document websocket connection was not observed",
          })
          .toBeGreaterThan(0);
      } finally {
        await Promise.allSettled(
          delayedSockets.map((socket) => socket.close({ code: 1001 })),
        );
        await delayedContext.close();
      }
    });

    await test.step("canonical direct access without bootstrap material does not render document-not-found", async () => {
      const noMaterialContext = await newE2EContext(browser, {
        bypassCSP: true,
        acceptDownloads: true,
      });
      const noMaterialPage = await noMaterialContext.newPage();

      try {
        await noMaterialPage.goto(`/share/d/${documentToken}#s=${shareSlug}`, {
          waitUntil: "domcontentloaded",
        });

        await expect(noMaterialPage).toHaveURL(
          new RegExp(`/share/${shareSlug}#s=${shareSlug}$`),
          {
            timeout: 30_000,
          },
        );
        await expectInvalidShareLinkWithoutDocumentNotFound(noMaterialPage);
      } finally {
        await noMaterialContext.close();
      }
    });

    await test.step("canonical direct access without share slug does not render document-not-found", async () => {
      const noSlugContext = await newE2EContext(browser, {
        bypassCSP: true,
        acceptDownloads: true,
      });
      const noSlugPage = await noSlugContext.newPage();

      try {
        await noSlugPage.goto(`/share/d/${documentToken}`, {
          waitUntil: "domcontentloaded",
        });

        await expect(noSlugPage).toHaveURL(new RegExp(`/share/d/${documentToken}$`), {
          timeout: 30_000,
        });
        await expectInvalidShareLinkWithoutDocumentNotFound(noSlugPage);
      } finally {
        await noSlugContext.close();
      }
    });

    await test.step("protected share landing prompts for a password and submits the unlock challenge", async () => {
    const protectedShareSlug = Buffer.alloc(16, 4).toString("base64url");
    const protectedDocumentToken = "mock-protected-doc";
    const challenge = Buffer.alloc(32, 7).toString("base64url");
    const salt = Buffer.alloc(16, 3).toString("base64url");
    const challengeBodies: Array<Record<string, unknown>> = [];
    const protectedContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    const protectedPage = await protectedContext.newPage();

    await protectedPage.route(`**/api/shares/${protectedShareSlug}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          share: {
            id: "00000000-0000-4000-8000-000000000000",
            document_id: "00000000-0000-4000-8000-000000000001",
            scope: "document",
            permission: "view",
            password_protected: true,
            password_capability_secret_commitment: MOCK_PASSWORD_CAPABILITY_SECRET_COMMITMENT,
            ...MOCK_SHARE_BOOTSTRAP_FIELDS,
          },
          root: {
            kind: "document",
            document_token: protectedDocumentToken,
          },
        }),
      });
    });

    await protectedPage.route(`**/api/shares/${protectedShareSlug}/challenge`, async (route) => {
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

      const challengeBody = (route.request().postDataJSON() ?? {}) as Record<string, unknown>;
      challengeBodies.push(challengeBody);
      const participantDeviceId =
        typeof challengeBody.share_participant_device_id === "string"
          ? challengeBody.share_participant_device_id
          : "00000000-0000-4000-8000-000000000011";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...MOCK_SHARE_BOOTSTRAP_FIELDS,
          password_capability_secret_commitment: MOCK_PASSWORD_CAPABILITY_SECRET_COMMITMENT,
          root: {
            kind: "document",
            document_token: protectedDocumentToken,
          },
          participant: {
            principal_id: "00000000-0000-4000-8000-000000000010",
            device_id: participantDeviceId,
            session_id: "00000000-0000-4000-8000-000000000012",
            grant: "view",
          },
        }),
      });
    });

    await protectedPage.goto(
      `/share/${protectedShareSlug}#cap=${MOCK_PROTECTED_CAPABILITY}&wpb=${MOCK_WPB_HASH}`,
      {
        waitUntil: "domcontentloaded",
      },
    );

    await expect(
      protectedPage.getByRole("heading", {
        name: "Enter password to continue",
      }),
    ).toBeVisible();

    await protectedPage.getByLabel("Password").fill("correct horse battery staple");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect
      .poll(() => challengeBodies.length, {
        timeout: 60_000,
        message: "challenge response request was not observed",
      })
      .toBe(1);

    expect(challengeBodies[0]?.display_name).toBe("Guest");
    expect(typeof challengeBodies[0]?.response).toBe("string");
    expect(challengeBodies[0]?.response).not.toBe("");
    await expect(protectedPage).toHaveURL(shareDocumentRouteRegex(protectedDocumentToken), {
      timeout: 30_000,
    });

    await protectedContext.close();
    });

    await test.step("protected share landing stays on the password prompt after an unlock failure and allows retry", async () => {
    const protectedShareSlug = Buffer.alloc(16, 5).toString("base64url");
    const protectedDocumentToken = "mock-protected-doc-retry";
    const challenge = Buffer.alloc(32, 9).toString("base64url");
    const salt = Buffer.alloc(16, 5).toString("base64url");
    const challengeBodies: Array<Record<string, unknown>> = [];
    const protectedContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    const protectedPage = await protectedContext.newPage();
    let respondAttempts = 0;

    await protectedPage.route(`**/api/shares/${protectedShareSlug}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          share: {
            id: "00000000-0000-4000-8000-000000000100",
            document_id: "00000000-0000-4000-8000-000000000101",
            scope: "document",
            permission: "view",
            password_protected: true,
            password_capability_secret_commitment: MOCK_PASSWORD_CAPABILITY_SECRET_COMMITMENT,
            ...MOCK_SHARE_BOOTSTRAP_FIELDS,
          },
          root: {
            kind: "document",
            document_token: protectedDocumentToken,
          },
        }),
      });
    });

    await protectedPage.route(`**/api/shares/${protectedShareSlug}/challenge`, async (route) => {
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

      const challengeBody = (route.request().postDataJSON() ?? {}) as Record<string, unknown>;
      challengeBodies.push(challengeBody);
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
          ...MOCK_SHARE_BOOTSTRAP_FIELDS,
          password_capability_secret_commitment: MOCK_PASSWORD_CAPABILITY_SECRET_COMMITMENT,
          root: {
            kind: "document",
            document_token: protectedDocumentToken,
          },
          participant: {
            principal_id: "00000000-0000-4000-8000-000000000110",
            device_id:
              typeof challengeBody.share_participant_device_id === "string"
                ? challengeBody.share_participant_device_id
                : "00000000-0000-4000-8000-000000000111",
            session_id: "00000000-0000-4000-8000-000000000112",
            grant: "view",
          },
        }),
      });
    });

    await protectedPage.goto(
      `/share/${protectedShareSlug}#cap=${MOCK_RETRY_PROTECTED_CAPABILITY}&wpb=${MOCK_WPB_HASH}`,
      {
        waitUntil: "domcontentloaded",
      },
    );

    await expect(
      protectedPage.getByRole("heading", {
        name: "Enter password to continue",
      }),
    ).toBeVisible({ timeout: 30_000 });
    await protectedPage.getByLabel("Password").fill("wrong password");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect(protectedPage.getByText("Share not found or password is invalid.")).toBeVisible({
      timeout: 30_000,
    });
    await expect(protectedPage).toHaveURL(
      new RegExp(
        `/share/${protectedShareSlug}#cap=${MOCK_RETRY_PROTECTED_CAPABILITY}&wpb=${MOCK_WPB_HASH}$`,
      ),
    );

    await protectedPage.getByLabel("Password").fill("correct horse battery staple");
    await protectedPage.getByRole("button", { name: "Unlock Share" }).click();

    await expect
      .poll(() => challengeBodies.length, {
        timeout: 15_000,
        message: "challenge retry request was not observed",
      })
      .toBe(2);

    await expect(protectedPage).toHaveURL(shareDocumentRouteRegex(protectedDocumentToken), {
      timeout: 30_000,
    });

    await protectedContext.close();
  });
  });
});
