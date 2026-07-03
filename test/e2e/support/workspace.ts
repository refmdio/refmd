import { expect, type Page } from "@playwright/test";
import { E2E_DELAYS } from "./timeouts";

export async function waitForWorkspaceReady(page: Page): Promise<void> {
  await expect
    .poll(async () => {
      return page.evaluate(() => {
        const workspaceId = localStorage.getItem("refmd_workspace_id");
        const trigger = document.querySelector<HTMLElement>(
          'aside [data-slot="dropdown-menu-trigger"]',
        );
        const workspaceName = trigger?.textContent?.trim() ?? "";
        const hasWorkspaceMenu =
          workspaceName.length > 0 && workspaceName !== "Select workspace";
        const hasWorkspaceSidebar = Array.from(document.querySelectorAll("aside button")).some(
          (button) => button.textContent?.trim() === "New Document",
        );
        const ready = !!workspaceId && (hasWorkspaceMenu || hasWorkspaceSidebar);
        return ready
          ? "ready"
          : JSON.stringify({
              workspaceId,
              workspaceName,
              hasWorkspaceMenu,
              hasWorkspaceSidebar,
              url: window.location.pathname,
              hasEditor: !!document.querySelector(
                '.cm-content, .ProseMirror, [data-testid="markdown-preview"]',
              ),
              bodyText: document.body.textContent?.trim().slice(0, 160) ?? "",
            });
      });
    }, {
      timeout: 120_000,
      message: "workspace selection was not initialized",
    })
    .toBe("ready");
}

export async function waitForWorkspaceReadyWithDiagnostics(
  page: Page,
  diagnostics: readonly string[],
): Promise<void> {
  try {
    await waitForWorkspaceReady(page);
  } catch (error) {
    const suffix =
      diagnostics.length > 0 ? `\n\nLogin diagnostics:\n${diagnostics.join("\n")}` : "";
    if (error instanceof Error) {
      throw new Error(`${error.message}${suffix}`, { cause: error });
    }
    throw error;
  }
}

export async function waitForWorkspaceReadyOrLogin(page: Page): Promise<boolean> {
  const deadline = Date.now() + 120_000;
  let lastState = "";
  while (Date.now() < deadline) {
    const state = await page.evaluate(() => {
      const workspaceId = localStorage.getItem("refmd_workspace_id");
      const trigger = document.querySelector<HTMLElement>(
        'aside [data-slot="dropdown-menu-trigger"]',
      );
      const workspaceName = trigger?.textContent?.trim() ?? "";
      const hasWorkspaceMenu = workspaceName.length > 0 && workspaceName !== "Select workspace";
      const hasWorkspaceSidebar = Array.from(document.querySelectorAll("aside button")).some(
        (button) => button.textContent?.trim() === "New Document",
      );
      const url = window.location.pathname;
      if (!!workspaceId && (hasWorkspaceMenu || hasWorkspaceSidebar)) return "ready";
      if (url === "/auth/login") return "login";
      return JSON.stringify({
        workspaceId,
        workspaceName,
        hasWorkspaceMenu,
        hasWorkspaceSidebar,
        url,
        hasEditor: !!document.querySelector(
          '.cm-content, .ProseMirror, [data-testid="markdown-preview"]',
        ),
        bodyText: document.body.textContent?.trim().slice(0, 160) ?? "",
      });
    });
    if (state === "ready") return true;
    if (state === "login") return false;
    lastState = state;
    await page.waitForTimeout(E2E_DELAYS.poll);
  }
  throw new Error(`workspace selection was not initialized: ${lastState}`);
}

async function resolveWorkspaceIdFromApi(page: Page, preferredName?: string): Promise<string> {
  return page.evaluate(async (targetName) => {
    const response = await fetch("/api/workspaces");
    if (!response.ok) {
      throw new Error(`failed to fetch workspaces: ${response.status}`);
    }
    const payload = (await response.json()) as {
      workspaces: Array<{ id: string; name: string; is_default?: boolean | null }>;
    };
    if (targetName) {
      const matched = payload.workspaces.find((workspace) => workspace.name === targetName);
      if (matched) return matched.id;
    }
    return (
      payload.workspaces.find((workspace) => workspace.is_default)?.id ??
      payload.workspaces[0]?.id ??
      ""
    );
  }, preferredName ?? null);
}

export async function createWorkspace(page: Page, name: string): Promise<void> {
  await page.locator('aside [data-slot="dropdown-menu-trigger"]').click();
  await page.getByRole("menuitem", { name: "New workspace" }).click();

  const dialog = page.locator('[role="dialog"]');
  await dialog.locator("#new-workspace-name").fill(name);
  const createButton = dialog.getByText("Create", { exact: true });
  await expect(createButton).toBeEnabled({ timeout: 60_000 });
  await createButton.click({ timeout: 60_000 });

  await waitForWorkspaceReady(page);
  await expect
    .poll(
      async () =>
        page.evaluate(() => {
          const trigger = document.querySelector<HTMLElement>(
            'aside [data-slot="dropdown-menu-trigger"]',
          );
          return trigger?.textContent?.trim() ?? "";
        }),
      {
        timeout: 180_000,
        message: `workspace ${name} was not selected after creation`,
      },
    )
    .toBe(name);
}

export async function switchWorkspace(page: Page, name: string): Promise<void> {
  await page.locator('aside [data-slot="dropdown-menu-trigger"]').click();
  await page.getByRole("menuitem", { name }).click();
  await expect(page).toHaveURL(/dashboard/, { timeout: 15_000 });
  await waitForWorkspaceReady(page);
  await expect
    .poll(
      async () =>
        page.evaluate(() => {
          const trigger = document.querySelector<HTMLElement>(
            'aside [data-slot="dropdown-menu-trigger"]',
          );
          return trigger?.textContent?.trim() ?? "";
        }),
      {
        timeout: 60_000,
        message: `workspace ${name} was not selected`,
      },
    )
    .toBe(name);
}

export async function currentWorkspaceId(page: Page): Promise<string> {
  await waitForWorkspaceReady(page);
  const { workspaceId, workspaceName } = await page.evaluate(() => {
    const trigger = document.querySelector<HTMLElement>('aside [data-slot="dropdown-menu-trigger"]');
    return {
      workspaceId: localStorage.getItem("refmd_workspace_id"),
      workspaceName: trigger?.textContent?.trim() ?? "",
    };
  });
  if (!workspaceId) {
    const resolved = await resolveWorkspaceIdFromApi(
      page,
      workspaceName.length > 0 ? workspaceName : undefined,
    );
    if (!resolved) {
      throw new Error("current workspace id not found in localStorage or API");
    }
    return resolved;
  }
  return workspaceId;
}

export async function fetchWorkspaceDocuments(page: Page, workspaceId?: string): Promise<
  Array<{
    id: string;
    title: string;
    doc_type: "document" | "folder";
    workspace_id: string;
  }>
> {
  const targetWorkspaceId = workspaceId ?? (await currentWorkspaceId(page));
  return page.evaluate(async (resolvedWorkspaceId) => {
    const response = await fetch(`/api/documents?workspace_id=${encodeURIComponent(resolvedWorkspaceId)}`);
    if (!response.ok) {
      throw new Error(`failed to fetch documents: ${response.status}`);
    }
    const payload = (await response.json()) as {
      documents: Array<{
        id: string;
        title: string;
        doc_type: "document" | "folder";
        workspace_id: string;
      }>;
    };
    return payload.documents;
  }, targetWorkspaceId);
}
