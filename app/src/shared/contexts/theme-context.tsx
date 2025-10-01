import React, { useCallback, useEffect, useMemo, useState } from 'react'

interface ThemeProviderProps { children: React.ReactNode }

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [theme, setTheme] = useState<string>(() => {
    try {
      const saved = localStorage.getItem('theme')
      if (saved === 'dark' || saved === 'light') return saved
      if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark'
      return 'light'
    } catch { return 'light' }
  })

  useEffect(() => {
    const root = document.documentElement
    if (theme === 'dark') root.classList.add('dark')
    else root.classList.remove('dark')
    try { localStorage.setItem('theme', theme) } catch {}

    try {
      const color = theme === 'dark' ? '#1e1e1e' : '#ffffff'
      const metas = Array.from(document.querySelectorAll('meta[name="theme-color"]')) as HTMLMetaElement[]
      if (metas.length === 0) {
        const meta = document.createElement('meta')
        meta.name = 'theme-color'
        document.head.appendChild(meta)
        metas.push(meta)
      }

      metas.forEach((meta) => {
        if (meta.hasAttribute('media')) meta.removeAttribute('media')
        meta.content = color
      })
    } catch {}
  }, [theme])
  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>
}

const ThemeContext = React.createContext<{ theme: string; setTheme: (t: string) => void } | null>(null)

export function useTheme() {
  const ctx = React.useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  const { theme, setTheme } = ctx
  const isDarkMode = theme === 'dark'
  const toggleTheme = useCallback(() => setTheme(isDarkMode ? 'light' : 'dark'), [isDarkMode, setTheme])
  return useMemo(() => ({ isDarkMode, toggleTheme, setTheme: (b: boolean) => setTheme(b ? 'dark' : 'light'), theme }), [isDarkMode, toggleTheme, setTheme, theme])
}
