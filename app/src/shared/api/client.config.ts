import { getGlobalStartContext } from '@tanstack/start-client-core'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { OpenAPI } from './client'

// Configure generated client at app startup
const resolvedBase = typeof window === 'undefined' ? getEnv('SSR_API_BASE_URL', API_BASE_URL) : API_BASE_URL

OpenAPI.BASE = resolvedBase
OpenAPI.WITH_CREDENTIALS = true
OpenAPI.CREDENTIALS = 'include'

let clientWorkspaceId: string | null = null

export function setClientWorkspaceId(workspaceId: string | null) {
  clientWorkspaceId = workspaceId
}

function resolveSSRRequestHeaders(): Record<string, string> | undefined {
  if (typeof window !== 'undefined') return undefined
  try {
    const context = getGlobalStartContext()
    const authContext = (context as { auth?: { requestHeaders?: Record<string, string> } } | undefined)?.auth
    return (
      authContext?.requestHeaders ?? (context as { requestHeaders?: Record<string, string> } | undefined)?.requestHeaders
    )
  } catch {
    return undefined
  }
}

OpenAPI.HEADERS = async (_options) => {
  const headers: Record<string, string> = {}

  // Attach workspace header for browser requests
  if (typeof window !== 'undefined') {
    if (clientWorkspaceId) {
      headers['X-Workspace-ID'] = clientWorkspaceId
    }
    return headers
  }

  const requestHeaders = resolveSSRRequestHeaders()
  if (requestHeaders) {
    const cookie = requestHeaders.cookie ?? requestHeaders.Cookie
    if (cookie) {
      headers.cookie = cookie
    }

    const forwardedProto = requestHeaders['x-forwarded-proto'] ?? requestHeaders['X-Forwarded-Proto']
    if (forwardedProto) {
      headers['x-forwarded-proto'] = forwardedProto
    }

    const forwardedHost = requestHeaders['x-forwarded-host'] ?? requestHeaders['X-Forwarded-Host'] ?? requestHeaders.host
    if (forwardedHost) {
      headers['x-forwarded-host'] = forwardedHost
    }

    const workspaceHeader = requestHeaders['x-workspace-id'] ?? requestHeaders['X-Workspace-ID']
    if (workspaceHeader) {
      headers['X-Workspace-ID'] = workspaceHeader
    }
  }

  return headers
}

OpenAPI.getSSRHeaders = resolveSSRRequestHeaders

OpenAPI.interceptors.response.use(async (response) => {
  const contentDisposition = response.headers.get('content-disposition') ?? ''
  const isAttachment = contentDisposition.toLowerCase().includes('attachment')

  let isDownloadPath = false
  try {
    const responseUrl = new URL(response.url)
    isDownloadPath = /\/download(?:[/?#]|$)/.test(responseUrl.pathname)
  } catch {
    isDownloadPath = response.url.includes('/download')
  }

  if (!isAttachment && !isDownloadPath) {
    return response
  }

  const contentType = response.headers.get('content-type') ?? ''
  const isJson = contentType.includes('application/json') || contentType.includes('+json')
  const isText = contentType.startsWith('text/')
  const isAlreadyBinary = ['application/octet-stream', 'application/pdf', 'application/zip'].some((prefix) =>
    contentType.includes(prefix),
  )

  if (contentType === '' || isJson || isText || isAlreadyBinary) {
    return response
  }

  const blob = await response.blob()
  const headers = new Headers(response.headers)
  headers.set('content-type', 'application/octet-stream')

  return new Response(blob, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
})
