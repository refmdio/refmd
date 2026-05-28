import {
  expect,
  type Page,
} from "@playwright/test";
import { E2E_DELAYS } from "../timeouts";
import { waitForWorkspaceReady } from "../workspace";
import { allowPluginConsentIfPresent } from "./consent";
import { pluginRuntimeDiagnostic } from "./diagnostics";
import {
  getSettingsDialog,
  returnToWorkspaceAfterPluginSettings,
} from "./settings";

export async function clickDocumentCreateButton(page: Page): Promise<void> {
  let lastError: unknown;
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    await allowPluginConsentIfPresent(page, 500, 30_000);
    const createButton = page.getByRole("button", { name: "Create" });
    if (
      (await createButton.isVisible({ timeout: 500 }).catch(() => false)) &&
      (await createButton.isEnabled().catch(() => false))
    ) {
      let clicked = false;
      await createButton.click({ timeout: 10_000 }).then(
        () => {
          clicked = true;
        },
        async (clickError) => {
          lastError = clickError;
          await createButton.click({ timeout: 5_000, force: true }).then(
            () => {
              clicked = true;
            },
            (forceClickError) => {
              lastError = forceClickError;
            },
          );
        },
      );
      if (clicked) return;
    }
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }
  throw new Error(`Create document button was not available after plugin consent handling: ${String(lastError ?? "")}`);
}

export async function createDocument(page: Page, title: string): Promise<void> {
  try {
    await allowPluginConsentIfPresent(page, 5_000, 30_000);
    await returnToWorkspaceAfterPluginSettings(page);
    await allowPluginConsentIfPresent(page, 10_000, 30_000);
    await waitForWorkspaceReady(page);

    const newDocumentButton = page.locator('[title="New Document"]');
    await expect(newDocumentButton).toBeVisible({ timeout: 20_000 });
    await expect(newDocumentButton).toBeEnabled({ timeout: 20_000 });
    await newDocumentButton.click({ force: true });

    const titleInput = page.locator('input[placeholder="Document title"]');
    await expect(titleInput).toBeVisible({ timeout: 10_000 });
    await expect
      .poll(
        async () => {
          await allowPluginConsentIfPresent(page, 500, 30_000);
          await titleInput.fill(title).catch(() => {});
          let value = await titleInput.inputValue().catch(() => "");
          if (value === title) return value;

          await titleInput.click({ timeout: 2_000 }).catch(() => {});
          await page.keyboard.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
          await page.keyboard.insertText(title);
          value = await titleInput.inputValue().catch(() => "");
          return value;
        },
        {
          timeout: 45_000,
          message: `document title input did not accept value ${title}`,
        },
      )
      .toBe(title);

    await submitDocumentCreateDialog(page, title);
    await allowPluginConsentIfPresent(page, 1_000, 30_000);
  } catch (error) {
    const settingsDialog = getSettingsDialog(page);
    const consentDialog = page.getByRole("dialog", { name: "Plugin Consent" });
    throw new Error(
      `Create document failed for ${title}:\nsettingsDialog=${await settingsDialog
        .textContent({ timeout: 1_000 })
        .catch(() => "<not visible>")}\nconsentDialog=${await consentDialog
        .textContent({ timeout: 1_000 })
        .catch(() => "<not visible>")}\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`,
    );
  }
}

export async function submitDocumentCreateDialog(page: Page, title: string): Promise<void> {
  const titleInput = page.locator('input[placeholder="Document title"]');
  const sidebarDocument = page.locator("aside").getByText(title);
  let lastError: unknown;
  const deadline = Date.now() + 120_000;

  while (Date.now() < deadline) {
    await allowPluginConsentIfPresent(page, 1_000, 30_000).catch((error) => {
      lastError = error;
    });
    if (await sidebarDocument.isVisible({ timeout: 500 }).catch(() => false)) return;

    if (await titleInput.isVisible({ timeout: 500 }).catch(() => false)) {
      const value = await titleInput.inputValue().catch(() => "");
      if (value !== title) {
        await titleInput.fill(title).catch((error) => {
          lastError = error;
        });
      }
      await clickDocumentCreateButton(page).catch((error) => {
        lastError = error;
      });
    }

    if (await sidebarDocument.isVisible({ timeout: 500 }).catch(() => false)) return;
    await page.waitForTimeout(E2E_DELAYS.shortPoll);
  }

  throw new Error(
    `Document ${title} was not created after dialog submit retries:\n${await pluginRuntimeDiagnostic(
      page,
    )}\n${String(lastError ?? "")}`,
  );
}
