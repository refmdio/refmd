import { type Page } from "@playwright/test";

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
