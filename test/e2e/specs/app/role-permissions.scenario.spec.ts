import { expect, test, type Page, type Response } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument, openDocument } from "../../support/documents";
import { openSettings, selectSettingsTab } from "../../support/settings";
import { waitForWorkspaceReady } from "../../support/workspace";

const DOCUMENT_TITLE = "Role permission replay";
const ROLE_NAME = "Restricted Writer";

test("role permission changes are signed, replayable, and invalidate write sessions", async ({
  browser,
}) => {
  test.setTimeout(300_000);
  const ownerContext = await newE2EContext(browser, { bypassCSP: true });
  const memberContext = await newE2EContext(browser, { bypassCSP: true });
  const ownerPage = await ownerContext.newPage();
  const memberPage = await memberContext.newPage();
  let memberSocketCloseCount = 0;
  memberPage.on("websocket", (socket) => socket.on("close", () => memberSocketCloseCount++));

  try {
    const { memberEmail, invitationLink } = await test.step("register users and create invitation", async () => {
      const ownerEmail = await registerAccount(ownerPage, "Role Owner");
      const email = await registerAccount(memberPage, "Role Member");
      expect(ownerEmail).not.toBe(email);
      await createDocument(ownerPage, DOCUMENT_TITLE);
      return { memberEmail: email, invitationLink: await inviteMember(ownerPage, email) };
    });

    await test.step("accept invitation and receive workspace keys", async () => {
      await acceptInvitation(memberPage, invitationLink, ownerPage);
    });

    await test.step("create a custom editor role", async () => {
      await createEditorRole(ownerPage);
    });

    await test.step("assign the custom editor role", async () => {
      const assignmentResponse = await assignRole(ownerPage, memberEmail);
      assertRoleChangeAccepted(assignmentResponse);
    });

    await test.step("deny write permission and disconnect the active member session", async () => {
      const closeCountBeforeWriteLoss = memberSocketCloseCount;
      const permissionResponse = await denyRoleWritePermission(ownerPage);
      assertRoleChangeAccepted(permissionResponse);
      await expect
        .poll(() => memberSocketCloseCount, {
          timeout: 30_000,
          message: "write permission loss did not disconnect the affected member socket",
        })
        .toBeGreaterThan(closeCountBeforeWriteLoss);
    });

    await test.step("reload and retain document read access", async () => {
      await memberPage.reload({ waitUntil: "domcontentloaded" });
      await waitForWorkspaceReady(memberPage);
      await openDocument(memberPage, DOCUMENT_TITLE);
      await expect(memberPage.locator("body")).not.toContainText("Failed to load document");
    });
  } finally {
    await ownerContext.close();
    await memberContext.close();
  }
});

async function inviteMember(ownerPage: Page, memberEmail: string): Promise<string> {
  await openSettings(ownerPage);
  await selectSettingsTab(ownerPage, "Workspace");
  await ownerPage.getByRole("button", { name: "Invite" }).click();
  const dialog = ownerPage.getByRole("dialog", { name: "Invite Member" });
  await dialog.locator("#invite-email").fill(memberEmail);
  await dialog.getByRole("button", { name: "Create Invitation" }).click();
  await expect(dialog.getByText("Invitation created")).toBeVisible({ timeout: 60_000 });
  const link = await dialog.locator("input[readonly]").inputValue();
  await dialog.getByRole("button", { name: "Done" }).click();
  await ownerPage.keyboard.press("Escape");
  return link;
}

async function acceptInvitation(memberPage: Page, link: string, ownerPage: Page): Promise<void> {
  await memberPage.goto(link, { waitUntil: "domcontentloaded" });
  const acceptButton = memberPage.getByRole("button", { name: /accept invitation/i });
  await expect(acceptButton).toBeVisible({ timeout: 30_000 });
  await acceptButton.click();

  const waiting = memberPage.getByText("Workspace key delivery is waiting for approval.");
  let acceptanceState = "pending";
  await expect
    .poll(
      async () => {
        if (/\/dashboard/.test(memberPage.url())) return (acceptanceState = "accepted");
        const body = await memberPage.locator("body").innerText();
        if (body.includes("joined the workspace")) return (acceptanceState = "accepted");
        if (body.includes("Workspace key delivery is waiting for approval.")) {
          return (acceptanceState = "waiting");
        }
        return (acceptanceState = "pending");
      },
      { timeout: 60_000 },
    )
    .not.toBe("pending");

  if (acceptanceState === "waiting") {
    await expect(waiting).toBeVisible();
    await openSettings(ownerPage);
    await selectSettingsTab(ownerPage, "Workspace");
    const approve = ownerPage.getByRole("button", { name: /approve key delivery/i }).first();
    await expect(approve).toBeVisible({ timeout: 30_000 });
    await approve.click();
    await expect(approve).toHaveCount(0, { timeout: 30_000 });
    await ownerPage.keyboard.press("Escape");
    await memberPage.getByRole("button", { name: "Retry" }).click();
  }

  await expect
    .poll(
      async () => {
        if (/\/dashboard/.test(memberPage.url())) return "accepted";
        const body = await memberPage.locator("body").innerText();
        return body.includes("joined the workspace") ? "accepted" : body.slice(0, 500);
      },
      { timeout: 60_000 },
    )
    .toBe("accepted");
  const goToWorkspace = memberPage.getByRole("button", { name: "Go to Workspace" });
  if (await goToWorkspace.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await goToWorkspace.click();
  }
  await expect.poll(() => /\/dashboard/.test(memberPage.url()), { timeout: 30_000 }).toBe(true);
  await waitForWorkspaceReady(memberPage);
}

async function createEditorRole(ownerPage: Page): Promise<void> {
  await openSettings(ownerPage);
  await selectSettingsTab(ownerPage, "Workspace");
  await ownerPage.getByRole("button", { name: "New Role" }).click();
  const dialog = ownerPage.getByRole("dialog", { name: "Create Role" });
  await dialog.locator("#role-name").fill(ROLE_NAME);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await expect(dialog).toHaveCount(0, { timeout: 30_000 });
  await expect(ownerPage.getByText(ROLE_NAME, { exact: true })).toBeVisible({ timeout: 30_000 });
}

async function assignRole(ownerPage: Page, memberEmail: string): Promise<Response> {
  const dialog = ownerPage.getByRole("dialog", { name: "Change Role" });
  await test.step("open member role dialog", async () => {
    const memberRow = ownerPage
      .locator("section")
      .filter({ hasText: "Members" })
      .getByText(memberEmail)
      .locator("..")
      .locator("..");
    const changeRole = memberRow.getByTitle("Change role");
    await expect(changeRole).toBeVisible({ timeout: 15_000 });
    await changeRole.click();
    await expect(dialog).toBeVisible({ timeout: 15_000 });
  });
  await test.step("select custom role", async () => {
    await dialog.locator('[data-slot="select-trigger"]').click({ timeout: 15_000 });
    const option = ownerPage.locator('[data-slot="select-item"]', { hasText: ROLE_NAME });
    await expect(option).toBeVisible({ timeout: 15_000 });
    await option.click();
  });
  return test.step("submit role assignment", async () => {
    const response = ownerPage.waitForResponse(
      (candidate) => isMemberRolePatch(candidate) && candidate.ok(),
      { timeout: 30_000 },
    );
    await dialog.getByRole("button", { name: "Change Role" }).click({ timeout: 15_000 });
    return response;
  });
}

async function denyRoleWritePermission(ownerPage: Page): Promise<Response> {
  const roleRow = ownerPage.getByText(ROLE_NAME, { exact: true }).locator("..").locator("..");
  await roleRow.getByTitle("Edit role").click();
  const dialog = ownerPage.getByRole("dialog", { name: `Edit Role: ${ROLE_NAME}` });
  const writePermission = dialog.getByRole("button").filter({ hasText: "Write documents" });
  await writePermission.click();
  await writePermission.click();
  await expect(writePermission).toContainText("Denied");
  const response = ownerPage.waitForResponse(
    (candidate) => isRolePatch(candidate) && candidate.ok(),
    { timeout: 30_000 },
  );
  await dialog.getByRole("button", { name: "Save" }).click({ timeout: 10_000 });
  return response;
}

function isMemberRolePatch(response: Response): boolean {
  return (
    response.request().method() === "PATCH" &&
    /\/api\/workspaces\/[^/]+\/members\/[^/]+$/.test(new URL(response.url()).pathname)
  );
}

function isRolePatch(response: Response): boolean {
  return (
    response.request().method() === "PATCH" &&
    /\/api\/workspaces\/[^/]+\/roles\/[^/]+$/.test(new URL(response.url()).pathname)
  );
}

function assertRoleChangeAccepted(response: Response): void {
  expect(response.ok(), `role update failed: ${response.status()}`).toBe(true);
}
