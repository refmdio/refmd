import React from 'react'

const isDev = import.meta.env.DEV

type LoadedModules = {
  Devtools: typeof import('@tanstack/react-devtools')['TanStackDevtools']
  RouterPanel: typeof import('@tanstack/react-router-devtools')['TanStackRouterDevtoolsPanel']
}

export function DevtoolsPortal() {
  const [mods, setMods] = React.useState<LoadedModules | null>(null)

  React.useEffect(() => {
    if (!isDev) return
    let cancelled = false

    ;(async () => {
      try {
        const [devtools, router] = await Promise.all([
          import('@tanstack/react-devtools'),
          import('@tanstack/react-router-devtools'),
        ])
        if (!cancelled) {
          setMods({ Devtools: devtools.TanStackDevtools, RouterPanel: router.TanStackRouterDevtoolsPanel })
        }
      } catch (error) {
        console.warn('[devtools] failed to load TanStack devtools', error)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [])

  if (!isDev || !mods) return null

  const { Devtools, RouterPanel } = mods
  return (
    <Devtools config={{ position: 'bottom-left' }} plugins={[{ name: 'Router Devtools', render: <RouterPanel /> }]} />
  )
}

export default DevtoolsPortal
