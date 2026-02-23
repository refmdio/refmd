/**
 * Invite Dialog
 *
 * UI shell for creating invitation links. Business logic (KEK fetching,
 * token generation, encryption, API calls) lives in the features layer.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/shared/ui/dialog'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/ui/dropdown-menu'
import { Spinner } from '@/shared/ui/spinner'
import { useAuthContext } from '@/shared/context'
import { useCreateInvitation } from '@/features/workspace-invite'
import type { components } from '@/shared/api'

type RoleDetail = components['schemas']['RoleDetailResponse']

interface InviteDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  workspaceId: string
  roles: RoleDetail[]
  onSuccess: () => void
}

export function InviteDialog({
  open,
  onOpenChange,
  workspaceId,
  roles,
  onSuccess,
}: InviteDialogProps) {
  const { auth, device } = useAuthContext()
  const { loading, error, setError, create } = useCreateInvitation()

  const [selectedRole, setSelectedRole] = useState<RoleDetail | null>(null)
  const [email, setEmail] = useState('')
  const [expiresInDays, setExpiresInDays] = useState('7')
  const [generatedLink, setGeneratedLink] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const assignableRoles = roles.filter(r => r.base_role !== 'owner')
  const defaultRole = assignableRoles.find(r => r.is_default) ?? assignableRoles[0] ?? null
  const activeRole = selectedRole ?? defaultRole

  const trimmedEmail = email.trim()
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)
  const showEmailError = trimmedEmail.length > 0 && !isValidEmail

  const handleCreate = async () => {
    if (!auth || !device || !activeRole || !email.trim()) return

    const result = await create({
      workspaceId,
      roleId: activeRole.id,
      email: email.trim(),
      expiresInDays: parseInt(expiresInDays, 10) || 7,
      userId: auth.userId,
      deviceId: device.deviceId,
      deviceKeys: device.deviceKeys,
      umk: auth.umk,
    })

    if (result) {
      setGeneratedLink(result.link)
      try {
        await navigator.clipboard.writeText(result.link)
        setCopied(true)
      } catch {
        // Clipboard write may fail (e.g. permissions, non-secure context).
        // The link is still visible in the input field for manual copying.
      }
      onSuccess()
    }
  }

  const handleClose = () => {
    setGeneratedLink(null)
    setCopied(false)
    setError(null)
    setSelectedRole(null)
    setEmail('')
    setExpiresInDays('7')
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Create invite link</DialogTitle>
        </DialogHeader>

        {generatedLink ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Invitation link created and copied to clipboard.
            </p>
            <div className="flex items-center gap-2">
              <Input
                readOnly
                value={generatedLink}
                className="text-xs font-mono"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(generatedLink)
                    setCopied(true)
                  } catch {
                    // Clipboard write may fail; link is still visible for manual copying.
                  }
                }}
              >
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
            <DialogFooter>
              <Button onClick={handleClose}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Email (required) */}
            <div className="space-y-2">
              <Label>Email</Label>
              <Input
                type="email"
                placeholder="user@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              {showEmailError && (
                <p className="text-xs text-destructive">Enter a valid email address</p>
              )}
            </div>

            {/* Role selection */}
            <div className="space-y-2">
              <Label>Role</Label>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="w-full justify-start">
                    {activeRole ? `${activeRole.name} (${activeRole.base_role})` : 'Select role...'}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent className="w-full">
                  {assignableRoles.map((role) => (
                    <DropdownMenuItem
                      key={role.id}
                      onClick={() => setSelectedRole(role)}
                    >
                      {role.name}
                      <span className="ml-2 text-xs text-muted-foreground">({role.base_role})</span>
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            {/* Expires in days */}
            <div className="space-y-2">
              <Label>Expires in (days)</Label>
              <Input
                type="number"
                min={1}
                max={30}
                value={expiresInDays}
                onChange={(e) => setExpiresInDays(e.target.value)}
              />
            </div>

            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={handleClose}>Cancel</Button>
              <Button onClick={handleCreate} disabled={loading || !activeRole || !isValidEmail}>
                {loading ? (
                  <>
                    <Spinner size="sm" className="mr-2" />
                    Creating...
                  </>
                ) : (
                  'Create & copy link'
                )}
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
