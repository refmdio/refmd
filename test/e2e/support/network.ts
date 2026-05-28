import { type Page, type Route } from "@playwright/test";

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
