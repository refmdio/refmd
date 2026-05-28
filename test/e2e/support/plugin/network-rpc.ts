import {
  expect,
  type Page,
} from "@playwright/test";
import {
  openSettings,
  selectSettingsTab,
} from "../settings";
import { safePageFrames } from "./diagnostics";
import {
  closeSettingsDialogIfOpen,
  getSettingsDialog,
} from "./settings";

export async function configureWorkspaceNetworkProxy(
  page: Page,
  endpointId = "network-demo-api",
): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "External");

  const dialog = getSettingsDialog(page);
  const section = dialog
    .getByRole("heading", { name: "Network Proxy" })
    .locator("xpath=ancestor::section[1]");
  await expect(section).toBeVisible({ timeout: 30_000 });

  await section.getByLabel("Proxy ID").fill("workspace-proxy");
  await section.getByLabel("Label").fill("Workspace Proxy");
  await section.getByLabel("Base URL").fill("https://proxy.example/refmd");
  await section.getByLabel("Operator").fill("Example NetOps");
  await section.getByLabel("Allowed Workspaces").fill("");
  await section.getByLabel("Allowed Users").fill("");
  await section.getByLabel("Verification Material").fill("{}");
  await section.getByLabel("Policy").fill(JSON.stringify({ allowed_endpoint_ids: [endpointId] }));

  const response = page.waitForResponse(
    (candidate) =>
      candidate.request().method() === "PATCH" &&
      /\/api\/workspaces\/[^/]+\/features$/.test(new URL(candidate.url()).pathname) &&
      candidate.ok(),
  );
  await section.getByRole("button", { name: "Save" }).click();
  await response;
  await closeSettingsDialogIfOpen(page);
}

export async function networkDemoFrameState(page: Page): Promise<{
  status: string | null;
  frameCount: number;
  frameTexts: string[];
}> {
  const frameTexts: string[] = [];
  let status: string | null = null;
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("RefMD Network Demo Plugin")) continue;
    frameTexts.push(state.bodyText.slice(0, 500));
    status = state.status;
  }
  return { status, frameCount: frameTexts.length, frameTexts };
}
