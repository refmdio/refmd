import {
  type Browser,
  type BrowserContext,
  type BrowserContextOptions,
  type BrowserType,
} from "@playwright/test";

const rateLimitBypassHeaders =
  process.env.E2E_RATE_LIMIT_BYPASS === "0"
    ? {}
    : {
        "X-RefMD-E2E-Rate-Limit-Bypass": "1",
      };
const chromium145LinuxUserAgent =
  process.env.E2E_CHROMIUM_USER_AGENT ??
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.6 Safari/537.36";

export const e2eBaseURL = process.env.BASE_URL || "http://localhost:4000";

type PersistentContextOptions = NonNullable<
  Parameters<BrowserType["launchPersistentContext"]>[1]
>;

function e2eContextOptions(
  browserName: string,
  options: BrowserContextOptions = {},
): BrowserContextOptions {
  const defaultUserAgent =
    browserName === "chromium" ? chromium145LinuxUserAgent : undefined;

  return {
    baseURL: e2eBaseURL,
    bypassCSP: true,
    ignoreHTTPSErrors: true,
    ...(defaultUserAgent && !options.userAgent ? { userAgent: defaultUserAgent } : {}),
    ...options,
    extraHTTPHeaders: {
      ...rateLimitBypassHeaders,
      ...options.extraHTTPHeaders,
    },
  };
}

export async function newE2EContext(
  browser: Browser,
  options: BrowserContextOptions = {},
): Promise<BrowserContext> {
  return browser.newContext(e2eContextOptions(browser.browserType().name(), options));
}

export async function launchPersistentE2EContext(
  browserType: BrowserType,
  userDataDir: string,
  options: PersistentContextOptions = {},
): Promise<BrowserContext> {
  return browserType.launchPersistentContext(
    userDataDir,
    e2eContextOptions(browserType.name(), options) as PersistentContextOptions,
  );
}
