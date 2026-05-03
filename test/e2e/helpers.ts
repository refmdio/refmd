import {
  expect,
  type Browser,
  type BrowserContext,
  type BrowserContextOptions,
  type Page,
  type Route,
} from "@playwright/test";

export const TEST_PASSWORD = "TestPassword123!";

const rateLimitBypassHeaders =
  process.env.E2E_RATE_LIMIT_BYPASS === "0"
    ? {}
    : {
        "X-RefMD-E2E-Rate-Limit-Bypass": "1",
      };

export async function newE2EContext(
  browser: Browser,
  options: BrowserContextOptions = {},
): Promise<BrowserContext> {
  return browser.newContext({
    ...options,
    extraHTTPHeaders: {
      ...rateLimitBypassHeaders,
      ...options.extraHTTPHeaders,
    },
  });
}

export function testEmail(): string {
  return `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.com`;
}

async function openRegisterForm(page: Page): Promise<void> {
  await page.goto("/auth/register");
  const nameInput = page.locator("#name");
  if (await nameInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
    return;
  }
  const registerLink = page.getByRole("link", { name: "Register" });
  if (await registerLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await registerLink.click();
  }
  await expect(nameInput).toBeVisible({ timeout: 60_000 });
}

export async function waitForWorkspaceReady(page: Page): Promise<void> {
  await expect
    .poll(async () => {
      return page.evaluate(() => {
        const workspaceId = localStorage.getItem("refmd_workspace_id");
        const trigger = document.querySelector<HTMLElement>(
          'aside [data-slot="dropdown-menu-trigger"]',
        );
        const workspaceName = trigger?.textContent?.trim() ?? "";
        return !!workspaceId && workspaceName.length > 0 && workspaceName !== "Select workspace";
      });
    }, {
      timeout: 120_000,
      message: "workspace selection was not initialized",
    })
    .toBe(true);
}

export async function blockApiRequests(page: Page): Promise<{
  blockedCount: () => number;
  unblock: () => Promise<void>;
}> {
  let blocked = 0;
  const context = page.context();
  const handler = async (route: Route) => {
    blocked += 1;
    await route.abort("internetdisconnected").catch(() => {});
  };

  await context.route("**/api/**", handler);

  return {
    blockedCount: () => blocked,
    unblock: () => context.unroute("**/api/**", handler),
  };
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

/**
 * Register a new account. Returns email for subsequent login.
 * Ends on the dashboard page.
 */
export async function registerAccount(page: Page, name = "E2E User"): Promise<string> {
  const email = testEmail();

  await openRegisterForm(page);
  const nameInput = page.locator("#name");
  await expect(nameInput).toBeVisible({ timeout: 60_000 });
  await nameInput.fill(name);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  // Argon2 key derivation + registration
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });

  // Complete recovery key step
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(1000);
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });

  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  await waitForWorkspaceReady(page);
  return email;
}

/**
 * Login with existing credentials. Ends on the dashboard page.
 */
export async function login(
  page: Page,
  email: string,
  options?: {
    allowDeviceRegistration?: boolean;
  },
): Promise<void> {
  const isWorkspaceVisible = async () =>
    page
      .getByRole("button", { name: "New Document" })
      .isVisible({ timeout: 2_000 })
      .catch(() => false);

  await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1_000);
  if (
    /\/dashboard/.test(page.url()) ||
    (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
    (await isWorkspaceVisible())
  ) {
    if (/\/dashboard/.test(page.url())) {
      await waitForWorkspaceReady(page);
    }
    return;
  }
  const emailInput = page.locator("#email");
  if (!(await emailInput.isVisible({ timeout: 5_000 }).catch(() => false))) {
    const signInButton = page.getByRole("button", { name: "Sign In" });
    if (await signInButton.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await signInButton.click();
    }
  }
  await expect
    .poll(
      async () => {
        if (
          /\/dashboard/.test(page.url()) ||
          (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
          (await isWorkspaceVisible())
        ) {
          return true;
        }
        return emailInput.isVisible({ timeout: 1_000 }).catch(() => false);
      },
      {
        timeout: 30_000,
        message: "login page never settled to dashboard, device registration, or email form",
      },
    )
    .toBe(true);
  if (
    /\/dashboard/.test(page.url()) ||
    (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
    (await isWorkspaceVisible())
  ) {
    if (/\/dashboard/.test(page.url())) {
      await waitForWorkspaceReady(page);
    }
    return;
  }
  await expect(emailInput).toBeVisible({ timeout: 30_000 });
  await emailInput.fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page).toHaveURL(
    options?.allowDeviceRegistration ? /dashboard|devices\/register/ : /dashboard/,
    { timeout: 120_000 },
  );
  if (/\/dashboard/.test(page.url())) {
    await waitForWorkspaceReady(page);
  }
}

export async function readEditorText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const fragments: string[] = [];
    const pushText = (value: string | null | undefined) => {
      const normalized = value?.replace(/\s+/g, " ").trim() ?? "";
      if (normalized.length > 0) fragments.push(normalized);
    };

    for (const node of document.querySelectorAll<HTMLElement>(".ProseMirror")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-content")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-editor")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-line")) {
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>('[role="textbox"]')) {
      pushText(node.innerText);
      pushText(node.textContent);
    }

    // Fallback for editor layouts where the rendered text is present in the
    // workspace body but not exposed through the editor-specific selectors.
    pushText(document.querySelector("main")?.textContent);
    pushText(document.body?.innerText);
    pushText(document.body?.textContent);

    return fragments.join("\n");
  });
}

export async function expectEditorTextContains(
  page: Page,
  snippet: string,
  timeout = 30_000,
): Promise<void> {
  await expect
    .poll(() => readEditorText(page), {
      timeout,
      message: `editor never contained expected text: ${snippet}`,
    })
    .toContain(snippet);
}

/**
 * Create a new document with the given title. Assumes dashboard is visible.
 */
export async function createDocument(page: Page, title: string): Promise<void> {
  await waitForWorkspaceReady(page);
  const newDocumentButton = page.locator('[title="New Document"]');
  await expect(newDocumentButton).toBeVisible({ timeout: 20_000 });
  await expect(newDocumentButton).toBeEnabled({ timeout: 20_000 });
  await newDocumentButton.click({ force: true });

  const titleInput = page.locator('input[placeholder="Document title"]');
  await expect(titleInput).toBeVisible({ timeout: 10_000 });
  await titleInput.fill(title);
  await page.getByText("Create", { exact: true }).click();

  await expect(page.locator("aside").getByText(title)).toBeVisible({
    timeout: 90_000,
  });
}

/**
 * Open a document by title from the sidebar.
 */
export async function openDocument(page: Page, title: string): Promise<void> {
  await waitForWorkspaceReady(page);

  const button = page.locator("aside").getByRole("button", { name: title });
  const row = page.locator("aside").getByText(title, { exact: true }).first();

  if (await button.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await expect
      .poll(async () => (await button.getAttribute("class")) ?? "", {
        timeout: 15_000,
        message: `document row did not become interactive: ${title}`,
      })
      .not.toContain("cursor-default");
    await button.click();
  } else {
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.click();
  }

  await expect
    .poll(
      async () =>
        page.evaluate(() => document.querySelectorAll("[data-panel-id]").length),
      {
        timeout: 5_000,
        message: `document panel did not open: ${title}`,
      },
    )
    .toBeGreaterThan(0);

  const deadline = Date.now() + 90_000;
  let lastState: {
    hasCm: boolean;
    hasPm: boolean;
    noDocumentsOpen: boolean;
    failedToLoad: boolean;
    disconnected: boolean;
    bodySnippet: string;
  } | null = null;

  while (Date.now() < deadline) {
    lastState = await page.evaluate(() => ({
      hasCm: !!document.querySelector(".cm-content"),
      hasPm: !!document.querySelector(".ProseMirror"),
      noDocumentsOpen: document.body.textContent?.includes("No documents open") ?? false,
      failedToLoad: document.body.textContent?.includes("Failed to load document") ?? false,
      disconnected: document.body.textContent?.includes("disconnected") ?? false,
      bodySnippet: document.body.textContent?.slice(0, 400) ?? "",
    }));

    if (lastState.hasCm || lastState.hasPm) return;
    await page.waitForTimeout(500);
  }

  throw new Error(`editor did not mount for ${title}: ${JSON.stringify(lastState)}`);
}

/**
 * Collect console errors during a callback.
 */
export async function collectErrors(
  page: Page,
  fn: () => Promise<void>,
): Promise<string[]> {
  const errors: string[] = [];
  const handler = (msg: { type: () => string; text: () => string }) => {
    if (msg.type() === "error") {
      errors.push(msg.text());
    }
  };
  page.on("console", handler);
  await fn();
  page.off("console", handler);
  return errors;
}

/**
 * Create a new folder with the given name. Assumes dashboard is visible.
 */
export async function createFolder(page: Page, name: string): Promise<void> {
  await page.waitForTimeout(2000);
  await page.locator('[title="New Folder"]').click();
  await page.waitForTimeout(1000);
  await page.locator('input[placeholder="Folder name"]').fill(name);
  await page.getByText("Create", { exact: true }).click();

  await expect(page.locator("aside").getByText(name)).toBeVisible({
    timeout: 90_000,
  });
}

/**
 * Right-click on a document/folder in the sidebar to open context menu.
 * Returns the active menu using the ARIA role exposed by the shared context-menu component.
 */
export async function openContextMenu(page: Page, title: string): Promise<ReturnType<Page["locator"]>> {
  await page.locator("aside").getByText(title).click({ button: "right" });
  const menu = page.getByRole("menu").last();
  await menu.waitFor({ state: "visible", timeout: 5_000 });
  return menu;
}

/**
 * Open the settings dialog from the sidebar user menu.
 */
export async function openSettings(page: Page): Promise<void> {
  await waitForWorkspaceReady(page);
  const settingsDialog = page.locator('[role="dialog"]').filter({
    has: page.getByRole("heading", { name: "Settings" }),
  });
  if (await settingsDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
    return;
  }

  const settingsButton = page.locator('button[aria-label="Settings"]');
  if (!(await settingsButton.isVisible({ timeout: 5_000 }).catch(() => false))) {
    const loginForm = page.locator("#email");
    if (await loginForm.isVisible({ timeout: 2_000 }).catch(() => false)) {
      throw new Error("settings unavailable because session is not active");
    }
  }
  await expect(page.locator('button[aria-label="Settings"]')).toBeVisible({ timeout: 20_000 });
  await page.locator('button[aria-label="Settings"]').click();
  await page.waitForTimeout(1000);
}

/**
 * Navigate to a tab within the settings dialog.
 */
export async function selectSettingsTab(page: Page, tabName: string): Promise<void> {
  await page.getByRole("tab", { name: tabName }).click();
  await page.waitForTimeout(500);
}

/**
 * Logout from the dashboard. Ends on the login page.
 */
export async function logout(page: Page): Promise<void> {
  const loginForm = page.locator("#email");
  if (await loginForm.isVisible({ timeout: 2_000 }).catch(() => false)) {
    return;
  }

  const settingsButton = page.locator('button[aria-label="Settings"]');
  if (!(await settingsButton.isVisible({ timeout: 5_000 }).catch(() => false))) {
    await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#email")).toBeVisible({ timeout: 10_000 });
    return;
  }

  await openSettings(page);
  await selectSettingsTab(page, "Account");
  await page.getByRole("button", { name: "Log out" }).click();
  await page.waitForTimeout(1000);

  // Confirm logout in dialog
  const confirmBtn = page.locator('[role="dialog"]').getByRole("button", { name: "Log out" });
  if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await confirmBtn.click();
  }

  await expect(page).toHaveURL(/auth\/login|\/$/,  { timeout: 10_000 });
}

export async function createWorkspace(page: Page, name: string): Promise<void> {
  await page.locator('aside [data-slot="dropdown-menu-trigger"]').click();
  await page.getByRole("menuitem", { name: "New workspace" }).click();

  const dialog = page.locator('[role="dialog"]');
  await dialog.locator("#new-workspace-name").fill(name);
  await dialog.getByText("Create", { exact: true }).click();

  await expect(page).toHaveURL(/dashboard/, { timeout: 30_000 });
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
        timeout: 30_000,
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
        timeout: 30_000,
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

export async function expectToast(page: Page, message: string): Promise<void> {
  await expect(page.locator('[data-sonner-toast]').getByText(message)).toBeVisible({
    timeout: 10_000,
  });
}

export async function indexedDbKeys(page: Page, storeName: string): Promise<string[]> {
  return page.evaluate(async (targetStoreName) => {
    return new Promise<string[]>((resolve) => {
      const request = indexedDB.open("refmd-offline");
      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(targetStoreName, "readonly");
        const store = transaction.objectStore(targetStoreName);
        const keysRequest = store.getAllKeys();
        keysRequest.onsuccess = () => {
          db.close();
          resolve(keysRequest.result.map((key) => String(key)));
        };
        keysRequest.onerror = () => {
          db.close();
          resolve([]);
        };
      };
      request.onerror = () => resolve([]);
    });
  }, storeName);
}
