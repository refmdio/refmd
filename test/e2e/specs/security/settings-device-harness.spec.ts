import { expect, test } from "@playwright/test";
import { registerAccount, TEST_PASSWORD } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  deviceRowByName,
  openSecuritySettings,
  renameCurrentDevice,
} from "../../support/security-settings";

test("settings helpers rename and select a removable device", async ({ browser }) => {
  test.setTimeout(240_000);
  const ownerContext = await newE2EContext(browser);
  const deviceContext = await newE2EContext(browser);
  const owner = await ownerContext.newPage();
  const device = await deviceContext.newPage();

  try {
    const email = await registerAccount(owner, "Settings Harness E2E");
    await device.goto("/auth/login");
    await device.locator("#email").fill(email);
    await device.locator("#password").fill(TEST_PASSWORD);
    await device.locator('button[type="submit"]').click();
    await expect(device).toHaveURL(/devices\/register/, { timeout: 120_000 });
    const approve = owner.getByRole("button", { name: /Emojis Match.*Approve/i });
    await expect(approve).toBeVisible({ timeout: 120_000 });
    await approve.click();
    await expect(device).toHaveURL(/dashboard/, { timeout: 120_000 });

    await renameCurrentDevice(device, "Settings Harness Target");
    await openSecuritySettings(owner);
    const row = deviceRowByName(owner, "Settings Harness Target");
    await row.getByTitle("Remove device").click({ timeout: 60_000 });
    await expect(owner.getByRole("heading", { name: "Remove Device" })).toBeVisible({
      timeout: 60_000,
    });
    await owner.getByRole("button", { name: "Cancel" }).click();
  } finally {
    await Promise.allSettled([deviceContext.close(), ownerContext.close()]);
  }
});
