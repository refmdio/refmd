import { lazy, Suspense } from 'react'

import type { MarkdownEditorProps } from '@/features/edit-document/ui/Editor'

const Editor = lazy(() => import('@/features/edit-document/ui/Editor'))

function Fallback() {
  return (
    <div className="h-full bg-background dark:bg-[#1e1e1e] relative flex flex-col">
      <div className="h-10 border-b bg-muted/30" />
      <div className="flex-1 flex items-center justify-center">
        <div className="text-muted-foreground">Loading editor...</div>
      </div>
    </div>
  )
}

export function MarkdownEditor(props: MarkdownEditorProps) {
  return (
    <Suspense fallback={<Fallback />}>
      <Editor {...props} />
    </Suspense>
  )
}

export default MarkdownEditor

