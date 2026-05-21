import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { settingsApi, type SettingsResponse } from "@/shared/api";
import { authState } from "@/entities/session";

function getSettingsKey() {
  const userId = authState()?.user?.id;
  return ["settings", userId ?? "anon"] as const;
}

export function useSettings() {
  const query = createQuery(() => ({
    queryKey: getSettingsKey(),
    queryFn: () => settingsApi.get(),
    staleTime: 5 * 60 * 1000,
    enabled: !!authState(),
  }));

  return query;
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();

  return createMutation(() => ({
    mutationFn: async (data: Partial<SettingsResponse>) => {
      const result = await settingsApi.update(data);
      return result;
    },
    onSuccess: (data) => {
      queryClient.setQueryData(getSettingsKey(), data);
    },
  }));
}
