/**
 * Recovery Page UI States
 *
 * Display components for the various states of the account recovery flow.
 */

import { useRef } from 'react'
import { Button } from '@/shared/ui/button'
import { Spinner } from '@/shared/ui/spinner'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

export function RecoveryLoadingState({ statusMessage }: { statusMessage: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 space-y-4">
      <Spinner size="lg" />
      <p className="text-muted-foreground">{statusMessage}</p>
    </div>
  )
}

export function RecoverySuccessState() {
  return (
    <div className="flex flex-col items-center justify-center py-12 space-y-4">
      <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
        <svg
          className="h-6 w-6 text-green-600"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M5 13l4 4L19 7"
          />
        </svg>
      </div>
      <p className="text-lg font-medium">Recovery Successful!</p>
      <p className="text-muted-foreground">Redirecting to your workspace…</p>
    </div>
  )
}

export function MnemonicWordGrid({
  words,
  onWordsChange,
  onFileUpload,
}: {
  words: string[]
  onWordsChange: (words: string[]) => void
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void
}) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const handleWordChange = (index: number, value: string) => {
    const newWords = [...words]

    if (value.includes(' ') && index === 0) {
      const pastedWords = value.trim().toLowerCase().split(/\s+/)
      if (pastedWords.length === 24) {
        onWordsChange(pastedWords)
        inputRefs.current[23]?.focus()
        return
      }
    }

    newWords[index] = value.toLowerCase().trim()
    onWordsChange(newWords)

    if (value && index < 23) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === 'ArrowRight' && index < 23) {
      inputRefs.current[index + 1]?.focus()
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowUp') {
      const newIndex = index - 4
      if (newIndex >= 0) inputRefs.current[newIndex]?.focus()
    } else if (e.key === 'ArrowDown') {
      const newIndex = index + 4
      if (newIndex < 24) inputRefs.current[newIndex]?.focus()
    } else if (e.key === 'Backspace' && !words[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label>Recovery Phrase</Label>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
        >
          Upload File
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt"
          onChange={onFileUpload}
          className="hidden"
        />
      </div>
      <p className="text-xs text-muted-foreground mb-4">
        Upload your recovery key file or enter each word manually. You can also paste the full 24-word phrase into the first field.
      </p>

      <div className="grid grid-cols-4 gap-2">
        {words.map((word, index) => (
          <div key={index} className="flex items-center gap-1">
            <span className="text-xs text-muted-foreground w-5 text-right">
              {index + 1}.
            </span>
            <Input
              ref={(el) => {
                inputRefs.current[index] = el
              }}
              type="text"
              value={word}
              onChange={(e) => handleWordChange(index, e.target.value)}
              onKeyDown={(e) => handleKeyDown(index, e)}
              placeholder="word"
              className="h-8 text-sm font-mono"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
            />
          </div>
        ))}
      </div>
    </div>
  )
}
