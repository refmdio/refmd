import { createQuery, createMutation, useQueryClient } from "@tanstack/solid-query";
import { settingsApi, type SettingsResponse } from "@/shared/api";
import { authState } from "@/shared/lib/auth-state";

function getSettingsKey() {
  const userId = authState()?.user?.id;
  return ["settings", userId ?? "anon"] as const;
}

function getCacheKey(): string | null {
  const userId = authState()?.user?.id;
  return userId ? `refmd_settings:${userId}` : null;
}

function cacheToLocalStorage(settings: SettingsResponse) {
  const key = getCacheKey();
  if (!key) return;
  try {
    localStorage.setItem(key, JSON.stringify(settings));
    localStorage.setItem(`${key}:ts`, String(Date.now()));
  } catch {
    // localStorage unavailable
  }
}

function readFromLocalStorage(): { data: SettingsResponse; updatedAt: number } | null {
  const key = getCacheKey();
  if (!key) return null;
  try {
    const cached = localStorage.getItem(key);
    const ts = localStorage.getItem(`${key}:ts`);
    if (cached && ts) {
      return { data: JSON.parse(cached) as SettingsResponse, updatedAt: Number(ts) };
    }
  } catch {
    // localStorage unavailable or corrupted
  }
  return null;
}

export function useSettings() {
  const cached = readFromLocalStorage();

  const query = createQuery(() => ({
    queryKey: getSettingsKey(),
    queryFn: async () => {
      const data = await settingsApi.get();
      cacheToLocalStorage(data);
      return data;
    },
    initialData: cached?.data,
    initialDataUpdatedAt: cached?.updatedAt,
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
      cacheToLocalStorage(result);
      return result;
    },
    onSuccess: (data) => {
      queryClient.setQueryData(getSettingsKey(), data);
    },
  }));
}
