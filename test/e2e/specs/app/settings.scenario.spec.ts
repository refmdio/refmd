import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument, openDocument } from "../../support/documents";
import { openSettings, selectSettingsTab } from "../../support/settings";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;
let email: string;
const guestDocumentTitle = "Guest Workspace Document";

async function guestRecoveryKeyNames(page: Page): Promise<string[]> {
  return page.evaluate(
    () =>
      new Promise<string[]>((resolve, reject) => {
        const request = indexedDB.open("refmd-keys");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const db = request.result;
          const transaction = db.transaction("keystore", "readonly");
          const keysRequest = transaction.objectStore("keystore").getAllKeys();
          keysRequest.onerror = () => reject(keysRequest.error);
          transaction.oncomplete = () => {
            db.close();
            resolve(
              keysRequest.result.filter(
                (key): key is string =>
                  typeof key === "string" &&
                  (key.startsWith("guest-pending-keys:") ||
                    key.startsWith("refmd-guest-redeem:") ||
                    key.startsWith("refmd-guest-active:")),
              ),
            );
          };
          transaction.onerror = () => reject(transaction.error);
        };
      }),
  );
}

async function auditCheckpointPinScopes(page: Page): Promise<string[]> {
  return page.evaluate(
    () =>
      new Promise<string[]>((resolve, reject) => {
        const request = indexedDB.open("refmd-security");
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const db = request.result;
          const transaction = db.transaction("audit-checkpoint-pins", "readonly");
          const keysRequest = transaction.objectStore("audit-checkpoint-pins").getAllKeys();
          keysRequest.onerror = () => reject(keysRequest.error);
          transaction.oncomplete = () => {
            db.close();
            resolve(keysRequest.result.filter((key): key is string => typeof key === "string"));
          };
          transaction.onerror = () => reject(transaction.error);
        };
      }),
  );
}

test.describe.serial("Settings Dialog", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    email = await registerAccount(sharedPage);
    await createDocument(sharedPage, guestDocumentTitle);
  });

  test("settings dialog exposes tabs, plugin controls, guest invites, and account state", async ({
    browser,
  }) => {
    test.setTimeout(E2E_TIMEOUTS.pluginInstall);

    await test.step("opens settings dialog with tab list", async () => {
      await openSettings(sharedPage);

      await expect(sharedPage.getByRole("tablist", { name: "Settings" })).toBeVisible({
        timeout: 5_000,
      });
    });

    await test.step("About tab is accessible", async () => {
      await selectSettingsTab(sharedPage, "About");

      await expect(sharedPage.getByRole("tab", { name: "About", selected: true })).toBeVisible({
        timeout: 5_000,
      });
    });

    await test.step("Security tab shows current device", async () => {
      await selectSettingsTab(sharedPage, "Security");

      await expect(sharedPage.getByText("Devices").first()).toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.getByText("(this device)")).toBeVisible({
        timeout: 5_000,
      });
    });

    await test.step("Workspace tab shows Members section", async () => {
      await selectSettingsTab(sharedPage, "Workspace");

      await expect(sharedPage.getByText("Members").first()).toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.getByText("Guest Invites", { exact: true })).toBeVisible({
        timeout: 5_000,
      });
      await expect(sharedPage.getByText("Allow guest invites", { exact: true })).toBeVisible({
        timeout: 5_000,
      });
      await expect(sharedPage.getByText("Share Links", { exact: true })).toBeVisible({
        timeout: 5_000,
      });
      await expect(sharedPage.getByText("Public Publishing", { exact: true })).toBeVisible({
        timeout: 5_000,
      });
      await expect(sharedPage.getByPlaceholder("Author name")).toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.getByPlaceholder("author-slug-base")).toBeVisible({ timeout: 5_000 });
    });

    await test.step("Community Plugins tab exposes add and management controls", async () => {
      await openSettings(sharedPage);
      await selectSettingsTab(sharedPage, "Community Plugins");

      const dialog = sharedPage.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
      await expect(dialog.getByRole("heading", { name: "Community Plugins" })).toBeVisible({
        timeout: 5_000,
      });
      await expect(dialog.getByRole("heading", { name: "Add Plugin" })).toBeVisible({
        timeout: 5_000,
      });
      await expect(dialog.getByRole("button", { name: "URL" })).toBeVisible({ timeout: 5_000 });
      await expect(dialog.getByRole("button", { name: "Upload" })).toBeVisible({
        timeout: 5_000,
      });
      await expect(dialog.getByRole("button", { name: "Personal" })).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "Workspace" })).toHaveCount(0);
      await expect(dialog.locator("textarea")).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "Review Plugin" })).toBeVisible({
        timeout: 5_000,
      });
      await expect(dialog.getByText("Create Candidate", { exact: true })).toHaveCount(0);
      await expect(dialog.getByText("Owner scope", { exact: true })).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "Approve Package" })).toHaveCount(0);
      await expect(dialog.getByRole("heading", { name: "Packages" })).toHaveCount(0);
      await expect(dialog.getByRole("heading", { name: "Activations" })).toHaveCount(0);
    });

    await test.step("Guest Invite dialog creates and redeems workspace guest invitations", async () => {
      await openSettings(sharedPage);
      await selectSettingsTab(sharedPage, "Workspace");

      const workspaceTab = sharedPage
        .locator('[role="dialog"]')
        .filter({ hasText: "Guest Invites" });
      const guestInvitesSection = workspaceTab.getByTestId("guest-invites-section");
      const allowGuestInvites = guestInvitesSection.getByText("Allow guest invites", {
        exact: true,
      });
      await expect(allowGuestInvites).toBeVisible({ timeout: 5_000 });

      if (
        !(await guestInvitesSection
          .getByRole("button", { name: "Invite Guest" })
          .isVisible()
          .catch(() => false))
      ) {
        const updateResponse = sharedPage.waitForResponse(
          (response) =>
            response.request().method() === "PATCH" &&
            response.url().includes("/api/workspaces/") &&
            !response.url().endsWith("/features"),
        );
        await guestInvitesSection.getByRole("group", { name: "Allow guest invites" }).click();
        await expect(guestInvitesSection.getByRole("switch").first()).toBeChecked({
          timeout: 10_000,
        });
        await guestInvitesSection.getByRole("button", { name: "Save" }).click();
        await updateResponse;
        await expect(guestInvitesSection.getByRole("button", { name: "Invite Guest" })).toBeVisible(
          {
            timeout: 30_000,
          },
        );
      }

      const createResponse = sharedPage.waitForResponse((response) => {
        const request = response.request();
        return (
          request.method() === "POST" &&
          /\/api\/workspaces\/[^/]+\/guest-invitations$/.test(response.url())
        );
      });

      await guestInvitesSection.getByRole("button", { name: "Invite Guest" }).click();
      const dialog = sharedPage
        .locator('[role="dialog"]')
        .filter({ has: sharedPage.getByRole("heading", { name: "Invite Guest" }) });
      await expect(dialog.getByRole("heading", { name: "Invite Guest" })).toBeVisible({
        timeout: 10_000,
      });
      await expect(dialog.getByText("Scope", { exact: true })).toHaveCount(0);
      await expect(dialog.getByText("Target", { exact: true })).toHaveCount(0);
      await dialog.getByRole("button", { name: "Create Invitation" }).click();

      const response = await createResponse;
      if (response.status() !== 201) {
        throw new Error(
          `guest invitation creation failed: ${response.status()} ${await response.text()}; request=${response.request().postData()}`,
        );
      }
      const payload = (await response.json()) as {
        invitation_id?: string;
        token_prefix?: string;
        scope_kind?: string;
        scope_id?: string | null;
      };
      expect(payload.invitation_id).toBeTruthy();
      expect(payload.token_prefix).toBeTruthy();
      expect(payload.scope_kind).toBe("workspace");
      expect(payload.scope_id).toBeNull();

      const inviteLinkInput = dialog.locator("input[readonly]").first();
      await expect(inviteLinkInput).toHaveValue(/\/invite#it=.+&ib=.+/, {
        timeout: 60_000,
      });
      const inviteLink = await inviteLinkInput.inputValue();
      await dialog.getByRole("button", { name: "Done" }).click();
      await expect(sharedPage.getByRole("heading", { name: "Invite Guest" })).not.toBeVisible({
        timeout: 10_000,
      });

      const guestContext = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
      await guestContext.addInitScript(() => {
        window.__REFMD_E2E__ = true;
        window.__refmdE2EClientLogs = [];
        window.addEventListener("refmd:client-log", (event) => {
          window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
        });
      });
      const guestPage = await guestContext.newPage();
      const apiErrors: string[] = [];
      const forbiddenBodies: string[] = [];
      const pageErrors: string[] = [];
      let workspaceResponse: unknown = null;
      const keyDirectoryResponses: unknown[] = [];
      guestPage.on("pageerror", (error) => pageErrors.push(error.message));
      guestPage.on("response", (response) => {
        if (!response.url().includes("/api/") || response.status() < 400) return;
        void response
          .text()
          .then((body) => {
            const entry = `${response.status()} ${response.url()} ${body}`;
            apiErrors.push(entry);
            if (response.status() === 403) forbiddenBodies.push(entry);
          })
          .catch(() => {});
      });
      guestPage.on("response", (response) => {
        if (
          response.request().method() === "GET" &&
          new URL(response.url()).pathname.endsWith("/key-directory/latest")
        ) {
          void response
            .json()
            .then((value) => {
              keyDirectoryResponses.push(value);
            })
            .catch(() => {});
        }
      });
      guestPage.on("response", (response) => {
        if (
          response.request().method() === "GET" &&
          new URL(response.url()).pathname === "/api/workspaces"
        ) {
          void response
            .json()
            .then((value) => {
              workspaceResponse = value;
            })
            .catch(() => {});
        }
      });

      try {
        await guestPage.goto(inviteLink, { waitUntil: "domcontentloaded" });
        await expect(guestPage.getByRole("button", { name: "Create Account" })).toHaveCount(0);
        await expect(guestPage.getByRole("button", { name: "Sign In" })).toHaveCount(0);
        await expect(guestPage.getByRole("button", { name: "Continue as Guest" })).toBeVisible({
          timeout: 30_000,
        });
        await guestPage.getByRole("button", { name: "Continue as Guest" }).click();
        const guestSucceeded = await expect
          .poll(
            async () => {
              if (/\/dashboard/.test(guestPage.url())) return true;
              const bodyText = await guestPage
                .locator("body")
                .innerText()
                .catch(() => "");
              return bodyText.includes("joined the workspace");
            },
            { timeout: 60_000, message: "guest invitation redemption did not succeed" },
          )
          .toBe(true)
          .then(() => true)
          .catch(() => false);
        if (!guestSucceeded) {
          const bodyText = await guestPage
            .locator("body")
            .innerText()
            .catch(() => "");
          const clientLogs = await guestPage.evaluate(() => window.__refmdE2EClientLogs ?? []);
          throw new Error(
            `guest invitation redemption did not succeed; url=${guestPage.url()}; body=${bodyText}; apiErrors=${apiErrors.join(" | ")}; pageErrors=${JSON.stringify(pageErrors)}; clientLogs=${JSON.stringify(clientLogs)}; workspaceResponse=${JSON.stringify(workspaceResponse)}`,
          );
        }
        await expect
          .poll(() => /\/dashboard/.test(guestPage.url()), { timeout: 30_000 })
          .toBe(true);
        await openDocument(guestPage, guestDocumentTitle).catch(async (error) => {
          const clientLogs = await guestPage.evaluate(() => window.__refmdE2EClientLogs ?? []);
          throw new Error(
            `${String(error)}; pageErrors=${JSON.stringify(pageErrors)}; clientLogs=${JSON.stringify(clientLogs)}; workspaceResponse=${JSON.stringify(workspaceResponse)}; keyDirectoryResponseCount=${keyDirectoryResponses.length}`,
          );
        });

        await guestPage.reload({ waitUntil: "domcontentloaded" });
        await openDocument(guestPage, guestDocumentTitle).catch(async (error) => {
          const clientLogs = await guestPage.evaluate(() => window.__refmdE2EClientLogs ?? []);
          throw new Error(
            `guest reload failed: ${String(error)}; apiErrors=${apiErrors.join(" | ")}; pageErrors=${JSON.stringify(pageErrors)}; clientLogs=${JSON.stringify(clientLogs)}`,
          );
        });

        await guestPage.goto(inviteLink, { waitUntil: "domcontentloaded" });
        const reenterButton = guestPage.getByRole("button", { name: "Continue as Guest" });
        await expect
          .poll(
            async () => {
              if (/\/dashboard/.test(guestPage.url())) return "reentered";
              if (await reenterButton.isVisible().catch(() => false)) return "confirm";
              return guestPage.locator("body").innerText();
            },
            { timeout: 30_000, message: "guest reentry did not start" },
          )
          .toMatch(/^(reentered|confirm)$/);
        if (await reenterButton.isVisible().catch(() => false)) {
          await reenterButton.click();
        }
        await expect
          .poll(() => /\/dashboard/.test(guestPage.url()), {
            timeout: 60_000,
            message: "admitted guest did not re-enter from the same invitation and device",
          })
          .toBe(true);
        await openDocument(guestPage, guestDocumentTitle);

        await expect
          .poll(
            () => {
              const matched = forbiddenBodies.filter(
                (body) =>
                  body.includes("rrp_missing_device_id") || body.includes("permission_denied"),
              );
              return matched.length === 0 ? false : matched.join(" | ");
            },
            {
              timeout: 2_000,
              message: "guest redemption/open must not hit RRP or member-list permission failures",
            },
          )
          .toBe(false);
      } finally {
        await guestContext.close();
      }

      await expect(guestInvitesSection.getByText(payload.token_prefix!)).toBeVisible({
        timeout: 10_000,
      });
      const revokeResponse = sharedPage.waitForResponse(
        (response) =>
          response.request().method() === "DELETE" &&
          response.url().includes(`/guest-invitations/${payload.invitation_id}`),
      );
      await guestInvitesSection.getByRole("button", { name: "Revoke invitation" }).click();
      await revokeResponse;
      await expect(guestInvitesSection.getByText(payload.token_prefix!)).toHaveCount(0, {
        timeout: 10_000,
      });
    });

    await test.step("Editor tab shows Default Editor Mode setting", async () => {
      await selectSettingsTab(sharedPage, "Editor");

      await expect(sharedPage.getByText("Default Editor Mode")).toBeVisible({
        timeout: 5_000,
      });
    });

    await test.step("Account tab shows user email", async () => {
      await selectSettingsTab(sharedPage, "Account");

      await expect(sharedPage.getByText(email)).toBeVisible({ timeout: 5_000 });
    });

    await test.step("Account tab has logout button", async () => {
      await expect(sharedPage.getByRole("button", { name: "Log out" })).toBeVisible({
        timeout: 5_000,
      });

      await sharedPage.keyboard.press("Escape");
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);
    });
  });

  test("signed audit checkpoint pins survive reload and settings reentry", async () => {
    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await expect(sharedPage).toHaveURL(/\/dashboard/);

    await expect
      .poll(() => auditCheckpointPinScopes(sharedPage), {
        timeout: 30_000,
        message: "signed user and workspace audit checkpoint pins were not retained",
      })
      .toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^user:/),
          expect.stringMatching(/^workspace:/),
        ]),
      );

    await openSettings(sharedPage);
    await selectSettingsTab(sharedPage, "Security");
    await expect(sharedPage.getByText("(this device)")).toBeVisible({ timeout: 5_000 });
  });

  test("registered guest recipient redeems a recipient-bound invitation", async ({ browser }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    const recipientContext = await newE2EContext(browser, { bypassCSP: true });
    await recipientContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      window.__refmdE2EClientLogs = [];
      window.addEventListener("refmd:client-log", (event) => {
        window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
      });
    });
    const recipientPage = await recipientContext.newPage();
    try {
      const recipientEmail = await registerAccount(recipientPage, "Known guest recipient");
      await openSettings(sharedPage);
      await selectSettingsTab(sharedPage, "Workspace");
      const guestInvitesSection = sharedPage.getByTestId("guest-invites-section");
      if (
        !(await guestInvitesSection
          .getByRole("button", { name: "Invite Guest" })
          .isVisible()
          .catch(() => false))
      ) {
        const updateResponse = sharedPage.waitForResponse(
          (response) =>
            response.request().method() === "PATCH" &&
            response.url().includes("/api/workspaces/") &&
            !response.url().endsWith("/features"),
        );
        await guestInvitesSection.getByRole("group", { name: "Allow guest invites" }).click();
        await expect(guestInvitesSection.getByRole("switch").first()).toBeChecked({
          timeout: 10_000,
        });
        await guestInvitesSection.getByRole("button", { name: "Save" }).click();
        await updateResponse;
        await expect(guestInvitesSection.getByRole("button", { name: "Invite Guest" })).toBeVisible(
          { timeout: 30_000 },
        );
      }
      await guestInvitesSection.getByRole("button", { name: "Invite Guest" }).click();
      const dialog = sharedPage
        .locator('[role="dialog"]')
        .filter({ has: sharedPage.getByRole("heading", { name: "Invite Guest" }) });
      await dialog.locator("#guest-email").fill(recipientEmail);
      const createResponse = sharedPage.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          response.status() === 201 &&
          /\/api\/workspaces\/[^/]+\/guest-invitations$/.test(response.url()),
      );
      await dialog.getByRole("button", { name: "Create Invitation" }).click();
      const payload = (await (await createResponse).json()) as { delivery_mode?: string };
      expect(payload.delivery_mode).toBe("known_recipient");
      const link = await dialog.locator("input[readonly]").inputValue();
      expect(link).toContain("/invite#it=");
      expect(link).not.toContain("&ib=");

      await recipientPage.goto(link, { waitUntil: "domcontentloaded" });
      const continueButton = recipientPage.getByRole("button", { name: "Continue as Guest" });
      await continueButton.waitFor({ state: "visible", timeout: 30_000 });
      await continueButton.click();
      await expect(
        recipientPage.getByText("Workspace key delivery is waiting for approval."),
      ).toBeVisible({ timeout: 30_000 });
      await dialog.getByRole("button", { name: "Done" }).click();
      const approveButton = guestInvitesSection
        .getByRole("button", { name: "Approve key delivery" })
        .first();
      await approveButton.waitFor({ state: "visible", timeout: 30_000 });
      await approveButton.click();
      await expect(approveButton).toHaveCount(0, { timeout: 30_000 });
      expect(await guestRecoveryKeyNames(recipientPage)).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^guest-pending-keys:/),
          expect.stringMatching(/^refmd-guest-redeem:/),
          expect.stringMatching(/^refmd-guest-active:/),
        ]),
      );

      const consumePattern = "**/api/guest/invitations/delivery-attempts/*/consume";
      let consumeRequestCount = 0;
      let committedResponseDropped = false;
      await recipientPage.route(consumePattern, async (route) => {
        consumeRequestCount += 1;
        if (committedResponseDropped) {
          await route.continue();
          return;
        }
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        committedResponseDropped = true;
        await route.abort("failed");
      });
      await recipientPage.getByRole("button", { name: "Retry" }).click();
      await expect
        .poll(() => committedResponseDropped, {
          timeout: 30_000,
          message: "guest consume response was not intercepted after commit",
        })
        .toBe(true);
      expect(consumeRequestCount).toBe(1);
      await expect
        .poll(
          async () => {
            if (/\/dashboard/.test(recipientPage.url())) return "redeemed";
            const bodyText = await recipientPage.locator("body").innerText();
            return JSON.stringify({ url: recipientPage.url(), bodyText });
          },
          { timeout: 60_000, message: "guest invitation redemption did not succeed" },
        )
        .toBe("redeemed");
      await recipientPage.unroute(consumePattern);

      await openDocument(recipientPage, guestDocumentTitle).catch(async (error) => {
        const clientLogs = await recipientPage.evaluate(() => window.__refmdE2EClientLogs ?? []);
        throw new Error(`${String(error)}\nclientLogs=${JSON.stringify(clientLogs)}`);
      });
      await recipientPage.reload({ waitUntil: "domcontentloaded" });
      await openDocument(recipientPage, guestDocumentTitle);

      const reentryDeliveryRequests: string[] = [];
      const recordReentryDeliveryRequest = (request: { url(): string }) => {
        if (request.url().includes("delivery-attempts")) {
          reentryDeliveryRequests.push(request.url());
        }
      };
      recipientPage.on("request", recordReentryDeliveryRequest);
      await recipientPage.goto(link, { waitUntil: "domcontentloaded" });
      const reenterButton = recipientPage.getByRole("button", { name: "Continue as Guest" });
      await expect
        .poll(
          async () => {
            if (/\/dashboard/.test(recipientPage.url())) return "reentered";
            if (await reenterButton.isVisible().catch(() => false)) return "confirm";
            return recipientPage.locator("body").innerText();
          },
          { timeout: 30_000, message: "known-recipient reentry did not start" },
        )
        .toMatch(/^(reentered|confirm)$/);
      if (await reenterButton.isVisible().catch(() => false)) {
        await reenterButton.click();
      }
      await expect
        .poll(() => /\/dashboard/.test(recipientPage.url()), {
          timeout: 60_000,
          message: "known recipient did not re-enter from the same invitation and device",
        })
        .toBe(true);
      recipientPage.off("request", recordReentryDeliveryRequest);
      expect(reentryDeliveryRequests).toEqual([]);
      await openDocument(recipientPage, guestDocumentTitle);
    } finally {
      await recipientContext.close();
    }
  });

  test("lost guest consume response and session discard the single-use attempt", async ({
    browser,
  }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    const recipientContext = await newE2EContext(browser, { bypassCSP: true });
    const recipientPage = await recipientContext.newPage();
    try {
      const recipientEmail = await registerAccount(recipientPage, "Lost guest session recipient");
      await openSettings(sharedPage);
      await selectSettingsTab(sharedPage, "Workspace");
      const guestInvitesSection = sharedPage.getByTestId("guest-invites-section");
      if (
        !(await guestInvitesSection
          .getByRole("button", { name: "Invite Guest" })
          .isVisible()
          .catch(() => false))
      ) {
        const updateResponse = sharedPage.waitForResponse(
          (response) =>
            response.request().method() === "PATCH" &&
            response.url().includes("/api/workspaces/") &&
            !response.url().endsWith("/features"),
        );
        await guestInvitesSection.getByRole("group", { name: "Allow guest invites" }).click();
        await guestInvitesSection.getByRole("button", { name: "Save" }).click();
        await updateResponse;
      }

      await guestInvitesSection.getByRole("button", { name: "Invite Guest" }).click();
      const dialog = sharedPage
        .locator('[role="dialog"]')
        .filter({ has: sharedPage.getByRole("heading", { name: "Invite Guest" }) });
      await dialog.locator("#guest-email").fill(recipientEmail);
      const createResponse = sharedPage.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          response.status() === 201 &&
          /\/api\/workspaces\/[^/]+\/guest-invitations$/.test(response.url()),
      );
      await dialog.getByRole("button", { name: "Create Invitation" }).click();
      await createResponse;
      const link = await dialog.locator("input[readonly]").inputValue();

      await recipientPage.goto(link, { waitUntil: "domcontentloaded" });
      await recipientPage.getByRole("button", { name: "Continue as Guest" }).click();
      await expect(
        recipientPage.getByText("Workspace key delivery is waiting for approval."),
      ).toBeVisible({ timeout: 30_000 });
      await dialog.getByRole("button", { name: "Done" }).click();
      const approveButton = guestInvitesSection
        .getByRole("button", { name: "Approve key delivery" })
        .first();
      await approveButton.click();
      await expect(approveButton).toHaveCount(0, { timeout: 30_000 });
      expect(await guestRecoveryKeyNames(recipientPage)).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^guest-pending-keys:/),
          expect.stringMatching(/^refmd-guest-redeem:/),
          expect.stringMatching(/^refmd-guest-active:/),
        ]),
      );

      const consumePattern = "**/api/guest/invitations/delivery-attempts/*/consume";
      let consumeRequestCount = 0;
      let committedResponseAndSessionDropped = false;
      await recipientPage.route(consumePattern, async (route) => {
        consumeRequestCount += 1;
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        await recipientContext.clearCookies();
        committedResponseAndSessionDropped = true;
        await route.abort("failed");
      });

      await recipientPage.getByRole("button", { name: "Retry" }).click();
      await expect
        .poll(() => committedResponseAndSessionDropped, {
          timeout: 30_000,
          message: "guest consume response and committed session were not dropped",
        })
        .toBe(true);
      await expect
        .poll(
          () =>
            recipientPage.evaluate(
              () =>
                Object.keys(localStorage).filter((key) =>
                  key.startsWith("refmd-invitation-delivery-attempt:"),
                ).length,
            ),
          { timeout: 30_000, message: "single-use guest delivery tuple was not discarded" },
        )
        .toBe(0);
      await expect
        .poll(() => guestRecoveryKeyNames(recipientPage), {
          timeout: 30_000,
          message: "guest pending keys or persisted redeem material were not discarded",
        })
        .toEqual([]);
      await recipientPage.waitForTimeout(E2E_DELAYS.poll * 2);
      expect(consumeRequestCount).toBe(1);
      expect(recipientPage.url()).not.toContain("/dashboard");
      await recipientPage.unroute(consumePattern);
    } finally {
      await recipientContext.close();
    }
  });
});
