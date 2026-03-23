import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  timeout: 300_000,
  workers: 1,
  retries: 0,
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:5173",
    bypassCSP: true,
    launchOptions: {
      args: ["--disable-web-security"],
    },
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
