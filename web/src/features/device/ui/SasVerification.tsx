/**
 * SAS Verification Component
 *
 * Displays 7 emojis for device verification
 * Used on both existing and new device to confirm matching
 */

import { cn } from '@/shared/lib/utils'

interface SasVerificationProps {
  /** 7 emojis to display */
  emojis: string
  /** Whether this is on the existing device (approving) or new device (waiting) */
  role: 'existing' | 'new'
  /** Optional className */
  className?: string
}

export function SasVerification({ emojis, role, className }: SasVerificationProps) {
  // Split emojis into array (handles multi-codepoint emojis)
  const emojiArray = [...emojis]

  return (
    <div className={cn('flex flex-col items-center gap-4', className)}>
      <div className="text-center">
        <h3 className="text-lg font-semibold mb-2">
          {role === 'existing' ? 'Verify New Device' : 'Verification Code'}
        </h3>
        <p className="text-sm text-muted-foreground">
          {role === 'existing'
            ? 'Compare these emojis with the new device'
            : 'Compare these emojis with your existing device'}
        </p>
      </div>

      <div className="flex justify-center gap-2 p-4 bg-muted rounded-lg">
        {emojiArray.map((emoji, index) => (
          <span
            key={index}
            className="text-4xl p-2 hover:scale-110 transition-transform"
            title={`Emoji ${index + 1}`}
          >
            {emoji}
          </span>
        ))}
      </div>

      <p className="text-xs text-muted-foreground text-center max-w-sm">
        {role === 'existing'
          ? 'Only approve if ALL 7 emojis match exactly. If they differ, your connection may be compromised.'
          : 'Wait for approval from your existing device after confirming the emojis match.'}
      </p>
    </div>
  )
}
