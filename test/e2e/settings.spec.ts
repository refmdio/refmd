import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  openSettings,
  selectSettingsTab,
  newE2EContext,
  createDocument,
  openDocument,
} from "./helpers";

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

  test("setup: register account", async () => {
    test.setTimeout(180_000);
    email = await registerAccount(sharedPage);
    await createDocument(sharedPage, guestDocumentTitle);
  });

  // SET-01
  test("opens settings dialog with tab list", async () => {
    test.setTimeout(10_000);
    await openSettings(sharedPage);

    await expect(
      sharedPage.getByRole("tablist", { name: "Settings" }),
    ).toBeVisible({ timeout: 5_000 });
  });

  // SET-02
  test("About tab is accessible", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "About");

    await expect(
      sharedPage.getByRole("tab", { name: "About", selected: true }),
    ).toBeVisible({ timeout: 5_000 });
  });

  // SET-03
  test("Security tab shows current device", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Security");

    await expect(sharedPage.getByText("Devices").first()).toBeVisible({ timeout: 5_000 });
    await expect(sharedPage.getByText("(this device)")).toBeVisible({
      timeout: 5_000,
    });
  });

  // SET-04
  test("Workspace tab shows Members section", async () => {
    test.setTimeout(10_000);
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

  // SET-05
  test("Guest Invite dialog creates and redeems workspace guest invitations", async ({
    browser,
  }) => {
    test.setTimeout(120_000);
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
      await guestInvitesSection.getByRole("group", { name: "Allow guest invites" }).click();
      await guestInvitesSection.getByRole("button", { name: "Save" }).click();
      await expect(guestInvitesSection.getByRole("button", { name: "Invite Guest" })).toBeVisible({
        timeout: 30_000,
      });
    }

    const createRequest = sharedPage.waitForRequest((request) => {
      return (
        request.method() === "POST" &&
        /\/api\/workspaces\/[^/]+\/guest-invitations$/.test(request.url())
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

    const request = await createRequest;
    const payload = request.postDataJSON() as {
      invitation_id?: string;
      token_prefix?: string;
      target_scope?: string;
      target_document_id?: string | null;
    };
    expect(payload.invitation_id).toBeTruthy();
    expect(payload.token_prefix).toBeTruthy();
    expect(payload.target_scope).toBe("workspace");
    expect(payload.target_document_id).toBeNull();

    const inviteLinkInput = dialog.locator("input[readonly]").first();
    await expect(inviteLinkInput).toHaveValue(/\/invite#token=/, {
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
          () =>
            forbiddenBodies.some(
              (body) =>
                body.includes("pop_missing_device_id") || body.includes("permission_denied"),
            ),
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

  // SET-06
  test("Editor tab shows Default Editor Mode setting", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Editor");

    await expect(sharedPage.getByText("Default Editor Mode")).toBeVisible({
      timeout: 5_000,
    });
  });

  // SET-07
  test("Account tab shows user email", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Account");

    await expect(sharedPage.getByText(email)).toBeVisible({ timeout: 5_000 });
  });

  // SET-08
  test("Account tab has logout button", async () => {
    test.setTimeout(10_000);

    await expect(
      sharedPage.getByRole("button", { name: "Log out" }),
    ).toBeVisible({ timeout: 5_000 });

    // Close settings
    await sharedPage.keyboard.press("Escape");
    await sharedPage.waitForTimeout(500);
  });
});
