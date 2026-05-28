import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  consentDescriptor,
  savePluginStatePin,
} from "../../support/plugin/consent";
import {
  ConsentDescriptor,
  PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
} from "../../support/plugin/types";
import { E2E_TIMEOUTS } from "../../support/timeouts";
import { waitForWorkspaceReady } from "../../support/workspace";

test("plugin consent decisions respect trusted state pins", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser, { bypassCSP: true });
  const page = await context.newPage();
  const consentRequests: Array<Record<string, unknown>> = [];
  let descriptor: ConsentDescriptor | null = null;

  await page.route(
    /\/api\/workspaces\/[^/]+\/plugin-runtime\/consent-required(?:\?.*)?$/,
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ applications: descriptor ? [descriptor] : [] }),
      });
    },
  );
  await page.route(
    /\/api\/workspaces\/[^/]+\/plugin-runtime(?:\?.*)?$/,
    async (route) => {
      if (route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ applications: descriptor ? [descriptor] : [] }),
      });
    },
  );
  await page.route(
    /\/api\/workspaces\/[^/]+\/plugin-applications\/[^/]+\/consent-events(?:\?.*)?$/,
    async (route) => {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      consentRequests.push(body);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          consent_event: {
            event_hash: body.event_hash,
            decision: body.decision,
            consent_epoch: body.consent_epoch,
          },
        }),
      });
    },
  );

  await registerAccount(page);
  const workspaceId = await page.evaluate(() => localStorage.getItem("refmd_workspace_id") ?? "");
  expect(workspaceId).not.toBe("");

  descriptor = consentDescriptor(workspaceId, "one");
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Plugin Consent" });
  await expect(dialog.getByRole("heading", { name: "Plugin Consent" })).toBeVisible({
    timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
  });

  const firstAllowButton = dialog.getByRole("button", { name: "Allow" });
  await expect(firstAllowButton).toBeEnabled({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
  await firstAllowButton.click({ timeout: 10_000 });
  await expect
    .poll(() => consentRequests.length, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS })
    .toBe(1);
  await expect(dialog).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
  expect(consentRequests.at(-1)?.decision).toBe("allow");

  descriptor = consentDescriptor(workspaceId, "two");
  await savePluginStatePin(page, descriptor);
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);

  const allowDialog = page.locator('[role="dialog"]').filter({ hasText: "Plugin Consent" });
  await expect(allowDialog.getByRole("heading", { name: "Plugin Consent" })).toBeVisible({
    timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
  });
  const secondAllowButton = allowDialog.getByRole("button", { name: "Allow" });
  await expect(secondAllowButton).toBeEnabled({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
  await secondAllowButton.click({ timeout: 10_000 });
  await expect
    .poll(() => consentRequests.length, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS })
    .toBe(2);
  await expect(allowDialog).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
  expect(consentRequests.at(-1)?.decision).toBe("allow");

  await context.close();
});
