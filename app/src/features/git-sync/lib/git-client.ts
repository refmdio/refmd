/**
 * Git Client for E2EE
 *
 * Uses isomorphic-git for client-side Git operations.
 * Network operations go through backend proxy (HTTPS) or tunnel (SSH).
 */

import * as git from 'isomorphic-git'
import type { HttpClient, GitHttpRequest, GitHttpResponse } from 'isomorphic-git'
import LightningFS from '@isomorphic-git/lightning-fs'
import type { GitCredentials } from './git-credentials'
import { API_BASE_URL } from '@/shared/lib/config'

/**
 * Parse Git SSH URL to extract host and repo
 */
export function parseGitSshUrl(url: string): { host: string; repo: string } {
  // Format: git@github.com:user/repo.git
  const match = url.match(/^git@([^:]+):(.+)$/)
  if (!match) {
    throw new Error(`Invalid SSH URL: ${url}`)
  }
  return { host: match[1], repo: match[2] }
}

/**
 * Git Client for E2EE environment
 */
export class GitClient {
  private _fs: LightningFS
  private pfs: LightningFS['promises']
  private _dir: string
  private proxyBaseUrl: string

  constructor(workspaceId: string) {
    this._fs = new LightningFS(`git-${workspaceId}`)
    this.pfs = this._fs.promises
    this._dir = '/repo'
    this.proxyBaseUrl = `${API_BASE_URL}/api/git/proxy`
  }

  /** Get the filesystem (for direct git operations) */
  get fs(): LightningFS {
    return this._fs
  }

  /** Get the repository directory path */
  get dir(): string {
    return this._dir
  }

  /**
   * Collect body from async iterator
   */
  private async collectBody(body: AsyncIterableIterator<Uint8Array> | undefined): Promise<Uint8Array | undefined> {
    if (!body) return undefined

    const chunks: Uint8Array[] = []
    for await (const chunk of body) {
      chunks.push(chunk)
    }

    if (chunks.length === 0) return undefined
    if (chunks.length === 1) return chunks[0]

    // Concatenate chunks
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    const result = new Uint8Array(totalLength)
    let offset = 0
    for (const chunk of chunks) {
      result.set(chunk, offset)
      offset += chunk.length
    }
    return result
  }

  /**
   * Create async iterator from Uint8Array
   */
  private async *toAsyncIterator(data: Uint8Array): AsyncIterableIterator<Uint8Array> {
    yield data
  }

  /**
   * Create HTTP client for HTTPS proxy
   */
  private createHttpsProxy(token: string): HttpClient {
    const proxyBaseUrl = this.proxyBaseUrl
    const collectBody = this.collectBody.bind(this)
    const toAsyncIterator = this.toAsyncIterator.bind(this)

    return {
      async request(req: GitHttpRequest): Promise<GitHttpResponse> {
        const proxyUrl = `${proxyBaseUrl}/https/${req.url.replace(/^https?:\/\//, '')}`

        const headers: Record<string, string> = {
          ...(req.headers || {}),
          Authorization: `Basic ${btoa(unescape(encodeURIComponent(`x-access-token:${token}`)))}`,
        }

        // Collect request body from async iterator
        const bodyData = await collectBody(req.body)

        const response = await fetch(proxyUrl, {
          method: req.method || 'GET',
          headers,
          body: bodyData ? new Blob([new Uint8Array(bodyData)]) : undefined,
          credentials: 'omit',
        })

        const responseBody = new Uint8Array(await response.arrayBuffer())

        return {
          url: response.url,
          method: req.method,
          statusCode: response.status,
          statusMessage: response.statusText,
          headers: Object.fromEntries(response.headers.entries()),
          body: responseBody.length > 0 ? toAsyncIterator(responseBody) : undefined,
        }
      },
    }
  }

  /**
   * Create HTTP client for SSH tunnel
   */
  private createSshProxy(privateKey: string, passphrase?: string): HttpClient {
    const proxyBaseUrl = this.proxyBaseUrl
    const collectBody = this.collectBody.bind(this)
    const toAsyncIterator = this.toAsyncIterator.bind(this)

    return {
      async request(req: GitHttpRequest): Promise<GitHttpResponse> {
        // Determine service from URL path
        const service = req.url.includes('git-upload-pack')
          ? 'git-upload-pack'
          : 'git-receive-pack'

        // Extract host and repo from URL
        // URL format: https://github.com/user/repo.git/info/refs?service=...
        const urlMatch = req.url.match(/https?:\/\/([^/]+)\/(.+?)(?:\/info\/refs|\/git-|$)/)
        if (!urlMatch) {
          throw new Error(`Cannot parse URL for SSH: ${req.url}`)
        }

        const host = urlMatch[1]
        const repo = urlMatch[2]

        // Collect request body from async iterator
        const bodyData = await collectBody(req.body)

        const response = await fetch(`${proxyBaseUrl}/ssh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            host,
            repo,
            service,
            private_key: privateKey,
            passphrase: passphrase || null,
            data: bodyData ? Array.from(bodyData) : [],
          }),
        })

        if (!response.ok) {
          const error = await response.text()
          throw new Error(`SSH tunnel error: ${error}`)
        }

        const result = await response.json()

        return {
          url: req.url,
          method: req.method,
          statusCode: 200,
          statusMessage: 'OK',
          headers: {},
          body: result.data ? toAsyncIterator(new Uint8Array(result.data)) : undefined,
        }
      },
    }
  }

  /**
   * Get HTTP client based on auth type
   */
  private getHttpClient(auth: GitCredentials): HttpClient {
    if (auth.authType === 'ssh') {
      if (!auth.privateKey) {
        throw new Error('SSH private key required')
      }
      return this.createSshProxy(auth.privateKey, auth.passphrase)
    }

    if (!auth.token) {
      throw new Error('Access token required')
    }
    return this.createHttpsProxy(auth.token)
  }

  /**
   * Initialize the repository directory
   */
  async ensureDir(): Promise<void> {
    try {
      await this.pfs.mkdir(this.dir)
    } catch (e) {
      // Directory may already exist
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw e
      }
    }
  }

  /**
   * Clone a repository
   */
  async clone(url: string, auth: GitCredentials): Promise<void> {
    await this.ensureDir()

    await git.clone({
      fs: this.fs,
      http: this.getHttpClient(auth),
      dir: this.dir,
      url,
      depth: 1,
      singleBranch: true,
      corsProxy: undefined, // Using our own proxy
    })
  }

  /**
   * Pull from remote
   */
  async pull(auth: GitCredentials): Promise<void> {
    await git.pull({
      fs: this.fs,
      http: this.getHttpClient(auth),
      dir: this.dir,
      author: { name: 'RefMD', email: 'sync@refmd.app' },
      singleBranch: true,
    })
  }

  /**
   * Push to remote
   */
  async push(auth: GitCredentials): Promise<void> {
    await git.push({
      fs: this.fs,
      http: this.getHttpClient(auth),
      dir: this.dir,
    })
  }

  /**
   * Fetch from remote
   */
  async fetch(auth: GitCredentials): Promise<void> {
    await git.fetch({
      fs: this.fs,
      http: this.getHttpClient(auth),
      dir: this.dir,
      singleBranch: true,
    })
  }

  /**
   * Add file to staging
   */
  async add(filepath: string): Promise<void> {
    await git.add({
      fs: this.fs,
      dir: this.dir,
      filepath,
    })
  }

  /**
   * Remove file from staging and working tree
   */
  async remove(filepath: string): Promise<void> {
    await git.remove({
      fs: this.fs,
      dir: this.dir,
      filepath,
    })
  }

  /**
   * Create a commit
   */
  async commit(message: string): Promise<string> {
    return git.commit({
      fs: this.fs,
      dir: this.dir,
      message,
      author: { name: 'RefMD', email: 'sync@refmd.app' },
    })
  }

  /**
   * Get status of all files
   */
  async status(): Promise<[string, number, number, number][]> {
    return git.statusMatrix({
      fs: this.fs,
      dir: this.dir,
    })
  }

  /**
   * Check if repository is initialized
   */
  async isInitialized(): Promise<boolean> {
    try {
      await git.findRoot({ fs: this.fs, filepath: this.dir })
      return true
    } catch {
      return false
    }
  }

  /**
   * Get current branch name
   */
  async currentBranch(): Promise<string | undefined> {
    return git.currentBranch({
      fs: this.fs,
      dir: this.dir,
    }) as Promise<string | undefined>
  }

  /**
   * List branches
   */
  async listBranches(): Promise<string[]> {
    return git.listBranches({
      fs: this.fs,
      dir: this.dir,
    })
  }

  /**
   * Get commit log
   */
  async log(depth: number = 10): Promise<git.ReadCommitResult[]> {
    return git.log({
      fs: this.fs,
      dir: this.dir,
      depth,
    })
  }

  /**
   * Write file to repository
   */
  async writeFile(filepath: string, content: string): Promise<void> {
    const fullPath = `${this.dir}/${filepath}`

    // Ensure parent directory exists
    const parentDir = fullPath.substring(0, fullPath.lastIndexOf('/'))
    if (parentDir && parentDir !== this.dir) {
      await this.mkdirp(parentDir)
    }

    await this.pfs.writeFile(fullPath, content, 'utf8')
  }

  /**
   * Read file from repository
   */
  async readFile(filepath: string): Promise<string> {
    const fullPath = `${this.dir}/${filepath}`
    const content = await this.pfs.readFile(fullPath, { encoding: 'utf8' })
    return content as string
  }

  /**
   * Delete file from repository
   */
  async deleteFile(filepath: string): Promise<void> {
    const fullPath = `${this.dir}/${filepath}`
    await this.pfs.unlink(fullPath)
  }

  /**
   * List files in directory
   */
  async listFiles(dirPath: string = ''): Promise<string[]> {
    const fullPath = dirPath ? `${this.dir}/${dirPath}` : this.dir
    return this.pfs.readdir(fullPath) as Promise<string[]>
  }

  /**
   * Create directory recursively
   */
  private async mkdirp(dirPath: string): Promise<void> {
    const parts = dirPath.split('/').filter(Boolean)
    let current = ''

    for (const part of parts) {
      current = current ? `${current}/${part}` : `/${part}`
      try {
        await this.pfs.mkdir(current)
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') {
          throw e
        }
      }
    }
  }

  /**
   * Clear repository (delete all files)
   */
  async clear(): Promise<void> {
    const files = await this.listFilesRecursive(this.dir)
    for (const file of files) {
      await this.pfs.unlink(file)
    }
  }

  /**
   * List all files recursively
   */
  private async listFilesRecursive(dirPath: string): Promise<string[]> {
    const result: string[] = []
    const entries = (await this.pfs.readdir(dirPath)) as string[]

    for (const entry of entries) {
      const fullPath = `${dirPath}/${entry}`
      const stat = await this.pfs.stat(fullPath)

      if (stat.isDirectory()) {
        if (entry !== '.git') {
          result.push(...(await this.listFilesRecursive(fullPath)))
        }
      } else {
        result.push(fullPath)
      }
    }

    return result
  }
}
