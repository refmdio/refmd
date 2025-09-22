import { QueryClient } from '@tanstack/react-query'

// Singleton QueryClient for use across loaders and providers
export const queryClient = new QueryClient()
