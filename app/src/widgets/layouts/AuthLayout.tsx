import React from 'react'

type Props = { children: React.ReactNode }

export default function AuthLayout({ children }: Props) {
  return (
    <div className="min-h-svh">{children}</div>
  )
}

