import { Suspense, lazy } from 'react'
import { HeadContent, Scripts, createRootRouteWithContext } from '@tanstack/react-router'

import { AuthProvider } from '@/shared/context/AuthContext'
import { ThemeProvider } from '@/shared/context/ThemeContext'
import type { RouterContext } from '@/router'

import appCss from '../styles.css?url'

const Devtools = import.meta.env.DEV
  ? lazy(async () => {
      const [{ TanStackRouterDevtoolsPanel }, { TanStackDevtools }] = await Promise.all([
        import('@tanstack/react-router-devtools'),
        import('@tanstack/react-devtools'),
      ])

      function DevtoolsInner() {
        return (
          <TanStackDevtools
            config={{
              position: 'bottom-right',
            }}
            plugins={[
              {
                name: 'Tanstack Router',
                render: <TanStackRouterDevtoolsPanel />,
              },
            ]}
          />
        )
      }

      return { default: DevtoolsInner }
    })
  : null

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => ({
    meta: [
      {
        charSet: 'utf-8',
      },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1',
      },
      {
        title: 'RefMD',
      },
    ],
    links: [
      {
        rel: 'stylesheet',
        href: appCss,
      },
    ],
  }),

  shellComponent: RootDocument,
})

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        <ThemeProvider>
          <AuthProvider>
            {children}
            {import.meta.env.DEV && Devtools ? (
              <Suspense fallback={null}>
                <Devtools />
              </Suspense>
            ) : null}
          </AuthProvider>
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  )
}
