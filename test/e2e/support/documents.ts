import { expect, type Page } from "@playwright/test";
import { E2E_DELAYS } from "./timeouts";
import { waitForWorkspaceReady } from "./workspace";

export async function createDocument(page: Page, title: string): Promise<void> {
  await waitForWorkspaceReady(page);
  const newDocumentButton = page.locator('[title="New Document"]');
  const titleInput = page.locator('input[placeholder="Document title"]');
  const createButton = page.getByRole("button", { name: "Create" });
  const sidebarDocument = page.locator("aside").getByText(title);
  const deadline = Date.now() + 180_000;
  let lastError: unknown;
  let lastSubmitAt = 0;

  while (Date.now() < deadline) {
    if ((await sidebarDocument.count().catch(() => 0)) > 0) return;

    if (lastSubmitAt > 0 && Date.now() - lastSubmitAt < 30_000) {
      await page.waitForTimeout(E2E_DELAYS.poll);
      continue;
    }

    if (!(await titleInput.isVisible({ timeout: 500 }).catch(() => false))) {
      await expect(newDocumentButton).toBeVisible({ timeout: 20_000 });
      await expect(newDocumentButton).toBeEnabled({ timeout: 20_000 });
      await newDocumentButton.click({ force: true }).catch((error) => {
        lastError = error;
      });
    }

    if (await titleInput.isVisible({ timeout: 2_000 }).catch(() => false)) {
      const accepted = await expect
        .poll(
          async () => {
            await titleInput.fill(title).catch((error) => {
              lastError = error;
            });
            let value = await titleInput.inputValue().catch(() => "");
            if (value === title) return value;

            await titleInput.click({ timeout: 2_000 }).catch((error) => {
              lastError = error;
            });
            await page.keyboard.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
            await page.keyboard.insertText(title);
            value = await titleInput.inputValue().catch(() => "");
            return value;
          },
          {
            timeout: 10_000,
            message: `document title input did not accept value ${title}`,
          },
        )
        .toBe(title)
        .then(
          () => true,
          (error) => {
            lastError = error;
            return false;
          },
        );

      if (accepted && (await createButton.isEnabled({ timeout: 5_000 }).catch(() => false))) {
        await createButton.click({ timeout: 10_000 }).catch(async (error) => {
          lastError = error;
          await createButton
            .evaluate((node) => {
              if (node instanceof HTMLElement) node.click();
            })
            .catch((evaluateError) => {
              lastError = evaluateError;
            });
        });
        lastSubmitAt = Date.now();
      }
    }

    if ((await sidebarDocument.count().catch(() => 0)) > 0) return;
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }

  const snapshot = await page
    .evaluate(() => ({
      url: window.location.href,
      bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
    }))
    .catch((error) => ({ diagnosticError: String(error) }));
  throw new Error(
    `Document ${title} was not created after retries: ${JSON.stringify(snapshot)}\n${String(
      lastError ?? "",
    )}`,
  );
}

export async function openDocument(page: Page, title: string): Promise<void> {
  await waitForWorkspaceReady(page);

  const button = page.locator("aside").getByRole("button", { name: title });
  const row = page.locator("aside").getByText(title, { exact: true }).first();

  const clickDocumentRow = async () => {
    const startedAt = Date.now();
    const deadline = startedAt + 90_000;
    let lastState: Awaited<ReturnType<typeof documentOpenFallbackState>> | null = null;

    while (Date.now() < deadline) {
      if (await button.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await expect
          .poll(async () => (await button.getAttribute("class")) ?? "", {
            timeout: 15_000,
            message: `document row did not become interactive: ${title}`,
          })
          .not.toContain("cursor-default");
        await button.click();
        return;
      }

      if (await row.isVisible({ timeout: 1_000 }).catch(() => false)) {
        await row.click();
        return;
      }

      lastState = await documentOpenFallbackState(page, title);
      if (Date.now() - startedAt > 30_000 && lastState.opened === true) {
        return;
      }

      await page.waitForTimeout(E2E_DELAYS.shortPoll);
    }

    throw new Error(`document row was not available for ${title}: ${JSON.stringify(lastState)}`);
  };

  await clickDocumentRow();

  await expect
    .poll(
      async () => {
        const opened = await page.evaluate(
          () =>
            document.querySelectorAll("[data-panel-id], .cm-content, .ProseMirror").length,
        );
        if (opened === 0) await clickDocumentRow();
        return opened;
      },
      {
        timeout: 15_000,
        message: `workspace tile did not open: ${title}`,
      },
    )
    .toBeGreaterThan(0);

  const deadline = Date.now() + 90_000;
  let lastState: {
    hasCm: boolean;
    hasPm: boolean;
    panelCount: number;
    url: string;
    workspaceId: string | null;
    noDocumentsOpen: boolean;
    failedToLoad: boolean;
    disconnected: boolean;
    bodySnippet: string;
    clientLogs: unknown[];
    sidebarButtons: unknown[];
    appDocuments: unknown;
    documentManagerState: unknown;
  } | null = null;

  while (Date.now() < deadline) {
    lastState = await page.evaluate(() => ({
      hasCm: !!document.querySelector(".cm-content"),
      hasPm: !!document.querySelector(".ProseMirror"),
      panelCount: document.querySelectorAll("[data-panel-id]").length,
      url: window.location.href,
      workspaceId: localStorage.getItem("refmd_workspace_id"),
      noDocumentsOpen: document.body.textContent?.includes("No documents open") ?? false,
      failedToLoad: document.body.textContent?.includes("Failed to load document") ?? false,
      disconnected: document.body.textContent?.includes("disconnected") ?? false,
      bodySnippet: document.body.textContent?.slice(0, 400) ?? "",
      clientLogs: (
        (window as Window & { __refmdE2EClientLogs?: unknown[] }).__refmdE2EClientLogs ?? []
      ).slice(-10),
      sidebarButtons: Array.from(document.querySelectorAll<HTMLElement>("aside button")).map(
        (button) => ({
          text: button.textContent?.trim() ?? "",
          className: button.getAttribute("class") ?? "",
          disabled: button.hasAttribute("disabled"),
          ariaCurrent: button.getAttribute("aria-current"),
        }),
      ),
      appDocuments:
        (window as Window & {
          __REFMD_APP_INSTANCE__?: {
            documents?: {
              getDocumentList?: () => unknown;
            };
          };
        }).__REFMD_APP_INSTANCE__?.documents?.getDocumentList?.() ?? null,
      documentManagerState: (() => {
        const documents = (window as Window & { __REFMD_APP_INSTANCE__?: { documents?: unknown } })
          .__REFMD_APP_INSTANCE__?.documents as
          | { openDocumentFn?: unknown; ops?: unknown; queryClient?: unknown; getWorkspaceId?: unknown }
          | undefined;
        return {
          hasOpenDocumentFn: typeof documents?.openDocumentFn === "function",
          hasOps: Boolean(documents?.ops),
          hasQueryClient: Boolean(documents?.queryClient),
          hasWorkspaceGetter: typeof documents?.getWorkspaceId === "function",
        };
      })(),
    })).catch(async (error) => {
      if (String(error).includes("Execution context was destroyed")) {
        await page.waitForLoadState("domcontentloaded").catch(() => undefined);
        return null;
      }
      throw error;
    });

    if (!lastState) {
      await page.waitForTimeout(E2E_DELAYS.poll);
      continue;
    }

    if (lastState.hasCm || lastState.hasPm) {
      return;
    }
    await page.waitForTimeout(E2E_DELAYS.poll);
  }

  throw new Error(
    `editor did not mount for ${title}: ${JSON.stringify({
      ...lastState,
    })}`,
  );
}

async function documentOpenFallbackState(
  page: Page,
  title: string,
): Promise<{
  appDocumentTitles: string[];
  bodySnippet: string;
  opened: boolean;
  sidebarButtons: string[];
  url: string;
  workspaceId: string | null;
}> {
  return page.evaluate((targetTitle) => {
    type AppDocument = {
      archivedAt?: unknown;
      docType?: string;
      id: string;
      title: string;
    };
    type AppDocumentManager = {
      getDocumentList?: () => AppDocument[];
      openDocument?: (id: string) => void;
    };

    const app = (
      window as Window & {
        __REFMD_APP_INSTANCE__?: {
          documents?: AppDocumentManager;
        };
      }
    ).__REFMD_APP_INSTANCE__;
    const documents = app?.documents;
    const appDocuments = documents?.getDocumentList?.() ?? [];
    const target = appDocuments.find(
      (document) =>
        document.title === targetTitle &&
        document.docType !== "folder" &&
        document.archivedAt == null,
    );
    const opened = Boolean(target && typeof documents?.openDocument === "function");
    if (target && typeof documents?.openDocument === "function") {
      documents.openDocument(target.id);
    }

    return {
      appDocumentTitles: appDocuments.map((document) => document.title),
      bodySnippet: document.body.textContent?.slice(0, 400) ?? "",
      opened,
      sidebarButtons: Array.from(document.querySelectorAll<HTMLElement>("aside button")).map(
        (button) => button.textContent?.trim() ?? "",
      ),
      url: window.location.href,
      workspaceId: localStorage.getItem("refmd_workspace_id"),
    };
  }, title);
}

export async function createFolder(page: Page, name: string): Promise<void> {
  await page.waitForTimeout(E2E_DELAYS.editorSettle);
  await page.locator('[title="New Folder"]').click();
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
  await page.locator('input[placeholder="Folder name"]').fill(name);
  await page.getByText("Create", { exact: true }).click();

  await expect(page.locator("aside").getByText(name)).toBeVisible({
    timeout: 90_000,
  });
}

export async function openContextMenu(page: Page, title: string): Promise<ReturnType<Page["locator"]>> {
  const sidebar = page.locator("aside");
  const buttonRow = sidebar.getByRole("button", { name: title }).first();
  const textRow = sidebar.getByText(title, { exact: true }).first();
  const row = (await buttonRow.isVisible({ timeout: 2_000 }).catch(() => false))
    ? buttonRow
    : textRow;

  await expect(row).toBeVisible({ timeout: 20_000 });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await row.click({ button: "right", force: true });
    const menu = page.getByRole("menu").last();
    if (await menu.isVisible({ timeout: 2_000 }).catch(() => false)) {
      return menu;
    }
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }

  const menu = page.getByRole("menu").last();
  await menu.waitFor({ state: "visible", timeout: 5_000 });
  return menu;
}
