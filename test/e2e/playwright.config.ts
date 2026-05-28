import { defineConfig } from "@playwright/test";
import { E2E_TIMEOUTS } from "./support/timeouts";

const rateLimitBypassHeaders =
  process.env.E2E_RATE_LIMIT_BYPASS === "0"
    ? {}
    : {
        "X-RefMD-E2E-Rate-Limit-Bypass": "1",
      };
const pluginSandboxSpecGlob = "sandbox/**/*.spec.ts";
const pluginSandboxDefaultSpecs = ["sandbox/runtime-boot.spec.ts"];
const pluginSandboxReleaseSpecs = ["sandbox/isolation.spec.ts"];
const requestedWorkers = Number.parseInt(process.env.E2E_WORKERS ?? "", 10);
const defaultWorkers = 4;
const normalWorkers =
  Number.isFinite(requestedWorkers) && requestedWorkers > 0 ? requestedWorkers : defaultWorkers;
const chromium145LinuxUserAgent =
  process.env.E2E_CHROMIUM_USER_AGENT ??
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.6 Safari/537.36";

export default defineConfig({
  testDir: "./specs",
  timeout: E2E_TIMEOUTS.extendedScenario,
  workers: normalWorkers,
  retries: 0,
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:4000",
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: rateLimitBypassHeaders,
  },
  projects: [
    // Keep project definitions independent of CLI test selection. Focused runs
    // should differ from full runs only by the selected test set.
    {
      name: "app-relaxed-chromium",
      testIgnore: pluginSandboxSpecGlob,
      use: {
        browserName: "chromium",
        userAgent: chromium145LinuxUserAgent,
        bypassCSP: true,
        launchOptions: { args: ["--disable-web-security"] },
      },
    },
    {
      name: "app-relaxed-firefox",
      testIgnore: pluginSandboxSpecGlob,
      use: {
        browserName: "firefox",
        bypassCSP: true,
        launchOptions: { args: ["--disable-web-security"] },
      },
    },
    {
      name: "sandbox-strict-chromium",
      testMatch: pluginSandboxDefaultSpecs,
      use: { browserName: "chromium", userAgent: chromium145LinuxUserAgent, bypassCSP: false },
    },
    {
      name: "sandbox-strict-firefox",
      testMatch: pluginSandboxDefaultSpecs,
      use: { browserName: "firefox", bypassCSP: false },
    },
    {
      name: "sandbox-release-strict-chromium",
      testMatch: pluginSandboxReleaseSpecs,
      use: {
        browserName: "chromium",
        userAgent: chromium145LinuxUserAgent,
        bypassCSP: false,
      },
    },
    {
      name: "sandbox-release-strict-firefox",
      testMatch: pluginSandboxReleaseSpecs,
      use: { browserName: "firefox", bypassCSP: false },
    },
  ],
});
