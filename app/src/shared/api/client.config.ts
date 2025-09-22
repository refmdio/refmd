import { API_BASE_URL } from '@/shared/lib/config'

import { OpenAPI } from './client'

// Configure generated client at app startup
OpenAPI.BASE = API_BASE_URL
OpenAPI.WITH_CREDENTIALS = true
OpenAPI.CREDENTIALS = 'include'
OpenAPI.HEADERS = async () => ({})
