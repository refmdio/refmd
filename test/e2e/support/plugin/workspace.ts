import {
  expect,
  type Page,
} from "@playwright/test";
import {
  openSettings,
  selectSettingsTab,
} from "../settings";
import { E2E_DELAYS } from "../timeouts";
import {
  switchWorkspace,
  waitForWorkspaceReady,
} from "../workspace";
import {
  closeOpenDialogOverlays,
  closeSettingsDialogIfOpen,
  getSettingsDialog,
} from "./settings";

export async function inviteWorkspaceMember(page: Page, email: string): Promise<string> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");

  const settingsDialog = getSettingsDialog(page);
  await expect(settingsDialog.getByRole("heading", { name: "Workspace" })).toBeVisible({
    timeout: 30_000,
  });
  await settingsDialog.getByRole("button", { name: "Invite" }).click();

  const inviteDialog = page.locator('[role="dialog"]').filter({
    has: page.getByRole("heading", { name: "Invite Member" }),
  });
  await expect(inviteDialog.getByRole("heading", { name: "Invite Member" })).toBeVisible({
    timeout: 30_000,
  });
  await inviteDialog.locator("#invite-email").fill(email);
  await inviteDialog.getByRole("button", { name: "Create Invitation" }).click();
  await expect(inviteDialog.getByText("Invitation created")).toBeVisible({ timeout: 60_000 });
  const link = await inviteDialog.locator("input[readonly]").inputValue();
  expect(link).toMatch(/\/invite#it=.+&ib=.+/);
  await inviteDialog.getByRole("button", { name: "Done" }).click();
  await expect(inviteDialog).toHaveCount(0, { timeout: 10_000 });
  if (await settingsDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
    await closeSettingsDialogIfOpen(page);
  }
  return link;
}

export async function acceptWorkspaceInvitation(page: Page, link: string): Promise<void> {
  await page.goto(link, { waitUntil: "domcontentloaded" });
  const acceptButton = page.getByRole("button", { name: /accept invitation/i });
  await expect(acceptButton).toBeVisible({ timeout: 30_000 });
  await acceptButton.click();
  await expect
    .poll(
      async () => {
        if (/\/dashboard/.test(page.url())) return "accepted";
        const text = await page.locator("body").innerText().catch(() => "");
        return text.includes("joined the workspace") ? "accepted" : text.slice(0, 240);
      },
      { timeout: 60_000, message: "workspace invitation acceptance did not succeed" },
    )
    .toBe("accepted");

  const goToWorkspace = page.getByRole("button", { name: "Go to Workspace" });
  if (await goToWorkspace.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await goToWorkspace.click();
  }

  await expect.poll(() => /\/dashboard/.test(page.url()), { timeout: 30_000 }).toBe(true);
  await waitForWorkspaceReady(page);
  await closeOpenDialogOverlays(page);
}

export async function leaveCurrentWorkspaceFromSettings(
  page: Page,
  previousWorkspaceName: string,
): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");

  const settingsDialog = getSettingsDialog(page);
  await expect(settingsDialog.getByRole("heading", { name: "Workspace" })).toBeVisible({
    timeout: 30_000,
  });
  await settingsDialog.locator("button", { hasText: /^Leave Workspace$/ }).click();

  const leaveDialog = page.locator('[role="dialog"]').filter({
    hasText: "You will lose access to all documents in this workspace.",
  });
  await expect(leaveDialog.getByRole("heading", { name: "Leave Workspace" })).toBeVisible({
    timeout: 30_000,
  });
  const memberDeleteResponses: string[] = [];
  const recordMemberDeleteResponse = (candidate: Awaited<ReturnType<Page["waitForResponse"]>>) => {
    const url = new URL(candidate.url());
    if (
      candidate.request().method() === "DELETE" &&
      /\/api\/workspaces\/[^/]+\/members\/[^/]+$/.test(url.pathname)
    ) {
      memberDeleteResponses.push(`${candidate.status()} ${url.pathname}`);
      void candidate
        .text()
        .then((body) => {
          if (body) memberDeleteResponses.push(`body=${body.slice(0, 1_000)}`);
        })
        .catch(() => {});
    }
  };
  page.on("response", recordMemberDeleteResponse);
  try {
    const response = page.waitForResponse(
      (candidate) => {
        const url = new URL(candidate.url());
        return (
          candidate.request().method() === "DELETE" &&
          /\/api\/workspaces\/[^/]+\/members\/[^/]+$/.test(url.pathname) &&
          candidate.ok()
        );
      },
      { timeout: 30_000 },
    );
    await leaveDialog.getByRole("button", { name: "Leave" }).click();
    await response.catch(async (error) => {
      await page.waitForTimeout(E2E_DELAYS.poll);
      throw new Error(
        `Workspace leave API did not complete successfully. Responses: ${memberDeleteResponses.join(", ") || "none"}. ${String(error)}`,
      );
    });
  } finally {
    page.off("response", recordMemberDeleteResponse);
  }
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
  await expect
    .poll(
      () =>
        page.evaluate(() => {
          const trigger = document.querySelector<HTMLElement>(
            'aside [data-slot="dropdown-menu-trigger"]',
          );
          return trigger?.textContent?.trim() ?? "";
        }),
      {
        timeout: 60_000,
        message: "workspace label did not change after member self-leave",
      },
    )
    .not.toBe(previousWorkspaceName);
  await expect(leaveDialog).toHaveCount(0, { timeout: 30_000 });
  if (await settingsDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
    await closeSettingsDialogIfOpen(page);
  }
}

export async function currentWorkspaceMenuLabel(page: Page): Promise<string> {
  await waitForWorkspaceReady(page);
  const label = await page.evaluate(() => {
    const trigger = document.querySelector<HTMLElement>('aside [data-slot="dropdown-menu-trigger"]');
    return trigger?.textContent?.trim() ?? "";
  });
  expect(label).not.toBe("");
  return label;
}

export async function ensureWorkspaceSelected(page: Page, name: string): Promise<void> {
  if ((await currentWorkspaceMenuLabel(page)) === name) return;
  await switchWorkspace(page, name);
}

export async function deleteCurrentWorkspaceFromSettings(page: Page): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");

  const dialog = getSettingsDialog(page);
  await expect(dialog.getByRole("heading", { name: "Workspace" })).toBeVisible({
    timeout: 30_000,
  });
  await dialog.getByRole("button", { name: "Delete Workspace" }).click();

  const deleteDialog = page.locator('[role="dialog"]').filter({
    hasText: "This action cannot be undone.",
  });
  await expect(deleteDialog.getByRole("heading", { name: "Delete Workspace" })).toBeVisible({
    timeout: 30_000,
  });
  const response = page.waitForResponse((candidate) => {
    const url = new URL(candidate.url());
    return (
      candidate.request().method() === "DELETE" &&
      /\/api\/workspaces\/[^/]+$/.test(url.pathname) &&
      candidate.ok()
    );
  });
  await deleteDialog.getByRole("button", { name: "Delete" }).click();
  await response;
  await expect(deleteDialog).toHaveCount(0, { timeout: 30_000 });
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
  await closeSettingsDialogIfOpen(page);
}
