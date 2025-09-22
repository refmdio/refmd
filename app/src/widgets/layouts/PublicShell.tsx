import { Calendar, ExternalLink, Github, MoreHorizontal, Moon, Sun } from 'lucide-react'
import React from 'react'

import { useTheme } from '@/shared/contexts/theme-context'
import { overlayMenuClass } from '@/shared/lib/overlay-classes'
import { Avatar, AvatarFallback } from '@/shared/ui/avatar'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/shared/ui/dropdown-menu'

type Props = {
  children: React.ReactNode
  pageType: 'document' | 'scrap' | 'list'
  showThemeToggle?: boolean
  title?: string
  subtitle?: string
  author?: { name?: string | null }
  publishedDate?: string
}

export default function PublicShell({ children, pageType, showThemeToggle = true, title, subtitle, author, publishedDate }: Props) {
  const { isDarkMode, toggleTheme } = useTheme()
  const pageBadgeText = pageType === 'document' ? 'Public Document' : pageType === 'scrap' ? 'Public Scrap' : 'Public Documents'
  const formattedPublishedDate = React.useMemo(() => {
    if (!publishedDate) return null
    try {
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(publishedDate))
    } catch {
      return publishedDate
    }
  }, [publishedDate])
  const authorName = author?.name?.trim()
  return (
    <div className="relative isolate min-h-screen bg-background text-foreground">
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-[-18rem] -z-10 overflow-hidden">
        <div className="mx-auto h-[28rem] w-[28rem] rounded-full bg-primary/20 blur-3xl sm:h-[32rem] sm:w-[32rem]" />
      </div>
      <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-[-18rem] -z-10 overflow-hidden">
        <div className="mx-auto h-[26rem] w-[26rem] rounded-full bg-muted/30 blur-3xl sm:h-[30rem] sm:w-[30rem]" />
      </div>

      <header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/65">
        <div className="mx-auto flex w-full max-w-6xl items-center gap-3 px-4 py-3 sm:px-6 md:px-10">
          <div className="flex items-center gap-2">
            <a href="/" className="text-lg font-semibold tracking-tight text-foreground transition-colors hover:text-primary">
              RefMD
            </a>
            <Badge variant="secondary" className="hidden sm:inline-flex rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide">
              {pageBadgeText}
            </Badge>
          </div>

          <div className="ml-auto flex items-center gap-2">
            {showThemeToggle && (
              <Button
                variant="ghost"
                size="sm"
                onClick={toggleTheme}
                className="h-9 w-9 rounded-full border border-transparent text-muted-foreground transition-colors hover:border-border hover:bg-muted/50 hover:text-foreground"
              >
                {isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </Button>
            )}
            <div className="hidden md:flex items-center gap-2">
              <Button variant="ghost" size="sm" asChild className="h-9 w-9 rounded-full text-muted-foreground hover:text-foreground">
                <a href="https://github.com/MuNeNICK/refmd" target="_blank" rel="noopener noreferrer">
                  <Github className="h-4 w-4" />
                </a>
              </Button>
              <Button variant="outline" size="sm" asChild className="rounded-full border-border/70 px-4 text-sm font-medium">
                <a href="/" className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span>Open RefMD</span>
                </a>
              </Button>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-9 w-9 rounded-full text-muted-foreground md:hidden">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className={overlayMenuClass}>
                {authorName && (
                  <>
                    <DropdownMenuLabel>Author</DropdownMenuLabel>
                    <DropdownMenuItem asChild>
                      <a href={`/u/${authorName}`} className="flex items-center gap-2">
                        <Avatar className="h-6 w-6 text-xs">
                          <AvatarFallback>{authorName.slice(0, 1).toUpperCase()}</AvatarFallback>
                        </Avatar>
                        <span className="font-medium">{authorName}</span>
                      </a>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                  </>
                )}
                <DropdownMenuItem asChild>
                  <a href="https://github.com/MuNeNICK/refmd" target="_blank" rel="noopener noreferrer" className="flex items-center">
                    <Github className="mr-2 h-4 w-4" /> GitHub
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href="/" className="flex items-center gap-2">
                    <ExternalLink className="h-4 w-4" />
                    <span>Open RefMD</span>
                  </a>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </header>

      <section className="relative z-10 mx-auto w-full max-w-6xl px-4 pt-10 sm:px-6 md:px-10">
        <div className="flex flex-col gap-6 rounded-3xl border border-border/60 bg-card/90 p-6 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-card/70 md:flex-row md:items-center md:justify-between md:gap-8">
          <div className="space-y-3">
            <Badge variant="secondary" className="inline-flex w-fit rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide md:hidden">
              {pageBadgeText}
            </Badge>
            {title ? (
              <h1 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
                {title}
              </h1>
            ) : (
              <h1 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">RefMD Public</h1>
            )}
            {subtitle && <p className="max-w-4xl text-base text-muted-foreground">{subtitle}</p>}
            {formattedPublishedDate && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Calendar className="h-4 w-4" />
                <span>Published {formattedPublishedDate}</span>
              </div>
            )}
          </div>

          {authorName && (
            <div className="flex items-center gap-3 rounded-2xl border border-border/60 bg-muted/30 px-4 py-3 shadow-sm">
              <Avatar className="h-11 w-11 text-base">
                <AvatarFallback>{authorName.slice(0, 1).toUpperCase()}</AvatarFallback>
              </Avatar>
              <div className="space-y-1 text-sm">
                <p className="font-semibold text-foreground">@{authorName}</p>
                <a
                  href={`/u/${authorName}`}
                  className="inline-flex items-center gap-1 text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
                >
                  View public profile
                </a>
              </div>
            </div>
          )}
        </div>
      </section>

      <main className="relative z-10 mx-auto w-full max-w-6xl px-4 pb-20 pt-10 sm:px-6 md:px-10">
        {children}
      </main>

      <footer className="relative z-10 border-t border-border/70 bg-background/80 py-10">
        <div className="mx-auto max-w-6xl px-4 text-center text-sm text-muted-foreground sm:px-6 md:px-10">
          <a href="https://github.com/MuNeNICK/refmd" target="_blank" rel="noopener noreferrer" className="transition-colors hover:text-foreground">
            Powered by RefMD
          </a>
        </div>
      </footer>
    </div>
  )
}
