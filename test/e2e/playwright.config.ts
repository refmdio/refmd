import { defineConfig } from "@playwright/test";

const rateLimitBypassHeaders =
  process.env.E2E_RATE_LIMIT_BYPASS === "0"
    ? {}
    : {
        "X-RefMD-E2E-Rate-Limit-Bypass": "1",
      };

export default defineConfig({
  testDir: ".",
  timeout: 300_000,
  workers: 1,
  retries: 0,
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:4000",
    bypassCSP: true,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: rateLimitBypassHeaders,
    launchOptions: {
      args: ["--disable-web-security"],
    },
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
    {
      name: "firefox",
      use: { browserName: "firefox" },
    },
  ],
});
