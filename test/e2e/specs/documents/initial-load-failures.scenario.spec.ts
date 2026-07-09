import { test, expect, type Page, type Route } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { E2E_TIMEOUTS } from "../../support/timeouts";

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

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await registerAccount(sharedPage);
    await createDocument(sharedPage, "RRP Failure Recovery Doc");
    await createDocument(sharedPage, "RRP Rate Limit Recovery Doc");
  });

  test("recovers from transient initial-load failures", async () => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("recover from a transient RRP challenge network failure", async () => {
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      const didInjectFailure = await failNextMatchingRequest(
        sharedPage,
        (url) => url.pathname === "/api/auth/rrp-challenge",
        (route) => route.abort("failed"),
      );

      const errors = await collectErrors(sharedPage, async () => {
        await openDocument(sharedPage, "RRP Failure Recovery Doc");
      });

      expect(didInjectFailure()).toBe(true);
      expect(hasInitialLoadFailure(errors)).toBe(false);
    });

    await test.step("recover from a transient RRP challenge rate limit", async () => {
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      const didInjectRateLimit = await failNextMatchingRequest(
        sharedPage,
        (url) => url.pathname === "/api/auth/rrp-challenge",
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
        await openDocument(sharedPage, "RRP Rate Limit Recovery Doc");
      });

      expect(didInjectRateLimit()).toBe(true);
      expect(hasInitialLoadFailure(errors)).toBe(false);
    });

    await test.step("retry rate-limited workspace key requests", async () => {
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
        await openDocument(sharedPage, title);
      });

      expect(didInjectRateLimit()).toBe(true);
      expect(hasInitialLoadFailure(errors)).toBe(false);
    });
  });
});
