import React from 'react'

import DevtoolsPortal from '@/widgets/layouts/DevtoolsPortal'

type Props = { children: React.ReactNode }

export default function PublicLayout({ children }: Props) {
  return (
    <div className="min-h-svh">
      {children}
      <DevtoolsPortal />
    </div>
  )
}
