import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;
let email: string;
const guestDocumentTitle = "Guest Workspace Document";

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

      await expect(
        sharedPage.getByRole("tablist", { name: "Settings" }),
      ).toBeVisible({ timeout: 5_000 });
    });

    await test.step("About tab is accessible", async () => {
      await selectSettingsTab(sharedPage, "About");

      await expect(
        sharedPage.getByRole("tab", { name: "About", selected: true }),
      ).toBeVisible({ timeout: 5_000 });
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

    const workspaceTab = sharedPage.locator('[role="dialog"]').filter({ hasText: "Guest Invites" });
    const guestInvitesSection = workspaceTab.getByTestId("guest-invites-section");
    const allowGuestInvites = guestInvitesSection.getByText("Allow guest invites", { exact: true });
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
      await expect(guestInvitesSection.getByRole("button", { name: "Invite Guest" })).toBeVisible({
        timeout: 30_000,
      });
    }

    const createResponse = sharedPage.waitForResponse((response) => {
      const request = response.request();
      return (
        request.method() === "POST" &&
        response.status() === 201 &&
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
    const guestPage = await guestContext.newPage();
    const apiErrors: string[] = [];
    const forbiddenBodies: string[] = [];
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
            const bodyText = await guestPage.locator("body").innerText().catch(() => "");
            return bodyText.includes("joined the workspace");
          },
          { timeout: 60_000, message: "guest invitation redemption did not succeed" },
        )
        .toBe(true)
        .then(() => true)
        .catch(() => false);
      if (!guestSucceeded) {
        const bodyText = await guestPage.locator("body").innerText().catch(() => "");
        throw new Error(
          `guest invitation redemption did not succeed; url=${guestPage.url()}; body=${bodyText}; apiErrors=${apiErrors.join(" | ")}`,
        );
      }
      await expect.poll(() => /\/dashboard/.test(guestPage.url()), { timeout: 30_000 }).toBe(true);
      await openDocument(guestPage, guestDocumentTitle);
      await expect
        .poll(
          () => {
            const matched = forbiddenBodies.filter(
              (body) =>
                body.includes("pop_missing_device_id") || body.includes("permission_denied"),
            );
            return matched.length === 0 ? false : matched.join(" | ");
          },
          {
            timeout: 2_000,
            message: "guest redemption/open must not hit PoP or member-list permission failures",
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
      await expect(
        sharedPage.getByRole("button", { name: "Log out" }),
      ).toBeVisible({ timeout: 5_000 });

      await sharedPage.keyboard.press("Escape");
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);
    });
  });
});
