import type { ReactNode } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'

interface AuthLayoutProps {
  title: string
  description: ReactNode
  children: ReactNode
  maxWidth?: 'md' | 'lg' | '2xl'
  titleClassName?: string
}

export function AuthLayout({
  title,
  description,
  children,
  maxWidth = 'md',
  titleClassName,
}: AuthLayoutProps) {
  const widthClass = maxWidth === '2xl' ? 'max-w-2xl' : maxWidth === 'lg' ? 'max-w-lg' : 'max-w-md'

  return (
    <main className="min-h-screen flex items-center justify-center p-4">
      <Card className={`w-full ${widthClass}`}>
        <CardHeader className="space-y-1">
          <CardTitle className={`text-2xl font-bold ${titleClassName ?? ''}`}>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>{children}</CardContent>
      </Card>
    </main>
  )
}
