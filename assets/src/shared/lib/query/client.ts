import { QueryClient } from "@tanstack/solid-query";
import { ApiError, getRateLimitRetryMs } from "@/shared/api/core";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error instanceof ApiError && [401, 403].includes(error.status)) {
          return false;
        }
        if (error instanceof ApiError && error.status === 429) {
          return failureCount < 2;
        }
        return failureCount < 3;
      },
      retryDelay: (_attemptIndex, error) => getRateLimitRetryMs(error) ?? 1000,
    },
    mutations: {
      retry: false,
    },
  },
});
