import { test, expect, type Page, type Route } from "@playwright/test";
import { collectErrors, createDocument, openDocument, registerAccount,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;

async function failNextMatchingRequest(
  page: Page,
  predicate: (url: URL) => boolean,
  fail: (route: Route) => Promise<void>,
): Promise<() => boolean> {
  let failed = false;
  await page.route(
    (url) => predicate(url),
    async (route) => {
      if (!failed) {
        failed = true;
        await fail(route);
        return;
      }
      await route.continue();
    },
  );
  return () => failed;
}

function hasInitialLoadFailure(errors: string[]): boolean {
  return errors.some((error) => error.includes("[ws] initial_load_failed"));
}

test.describe.serial("Document Initial Load Failure Handling", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account and create documents", async () => {
    test.setTimeout(300_000);

    await registerAccount(sharedPage);
    await createDocument(sharedPage, "PoP Failure Recovery Doc");
    await createDocument(sharedPage, "PoP Rate Limit Recovery Doc");
  });

  test("recovers from a transient PoP challenge network failure during initial open", async () => {
    test.setTimeout(120_000);

    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const didInjectFailure = await failNextMatchingRequest(
      sharedPage,
      (url) => url.pathname === "/api/auth/pop-challenge",
      (route) => route.abort("failed"),
    );

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, "PoP Failure Recovery Doc", 0);
    });

    expect(didInjectFailure()).toBe(true);
    expect(hasInitialLoadFailure(errors)).toBe(false);
  });

  test("recovers from a transient PoP challenge rate limit during initial open", async () => {
    test.setTimeout(120_000);

    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const didInjectRateLimit = await failNextMatchingRequest(
      sharedPage,
      (url) => url.pathname === "/api/auth/pop-challenge",
      (route) =>
        route.fulfill({
          status: 429,
          headers: {
            "content-type": "application/json",
            "retry-after": "1",
          },
          body: JSON.stringify({
            error: "rate_limit_exceeded",
            retry_after: 1,
          }),
        }),
    );

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, "PoP Rate Limit Recovery Doc", 0);
    });

    expect(didInjectRateLimit()).toBe(true);
    expect(hasInitialLoadFailure(errors)).toBe(false);
  });

  test("retries rate-limited workspace key requests during initial open", async () => {
    test.setTimeout(120_000);

    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const title = `Workspace Key Recovery Doc ${Date.now()}`;
    await createDocument(sharedPage, title);
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });

    const didInjectRateLimit = await failNextMatchingRequest(
      sharedPage,
      (url) => /^\/api\/workspaces\/[^/]+\/member-keys$/.test(url.pathname),
      (route) =>
        route.fulfill({
          status: 429,
          headers: {
            "content-type": "application/json",
            "retry-after": "1",
          },
          body: JSON.stringify({
            error: "rate_limit_exceeded",
            retry_after: 1,
          }),
        }),
    );

    const errors = await collectErrors(sharedPage, async () => {
      await openDocument(sharedPage, title, 0);
    });

    expect(didInjectRateLimit()).toBe(true);
    expect(hasInitialLoadFailure(errors)).toBe(false);
  });
});
