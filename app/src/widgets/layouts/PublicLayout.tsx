import React from 'react'

import DevtoolsPortal from '@/shared/ui/devtools/DevtoolsPortal'

type Props = { children: React.ReactNode }

export default function PublicLayout({ children }: Props) {
  return (
    <div className="min-h-svh">
      {children}
      <DevtoolsPortal />
    </div>
  )
}
