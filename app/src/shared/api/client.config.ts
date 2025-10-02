import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { OpenAPI } from './client'

// Configure generated client at app startup
const resolvedBase = typeof window === 'undefined' ? getEnv('SSR_API_BASE_URL', API_BASE_URL) : API_BASE_URL

OpenAPI.BASE = resolvedBase
OpenAPI.WITH_CREDENTIALS = true
OpenAPI.CREDENTIALS = 'include'
OpenAPI.HEADERS = async () => ({})
