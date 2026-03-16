import { client, throwIfError } from "./core";
import type { components } from "./schema";

export type SettingsResponse = components["schemas"]["SettingsResponse"];
export type UpdateSettingsRequest = components["schemas"]["UpdateSettingsRequest"];

export const settingsApi = {
  get: async () => throwIfError(await client.GET("/api/settings")),

  update: async (body: UpdateSettingsRequest) =>
    throwIfError(await client.PATCH("/api/settings", { body })),
};
