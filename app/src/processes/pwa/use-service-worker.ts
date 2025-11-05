import { useEffect } from 'react'

export function useServiceWorker() {
  useEffect(() => {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
      return
    }

    let isMounted = true

    const register = async () => {
      const { registerSW } = await import('virtual:pwa-register')

      if (!isMounted) {
        return
      }

      registerSW({
        immediate: true,
        onRegistered: (registration) => {
          if (import.meta.env.DEV) {
            console.info('[pwa] service worker registered', registration)
          }
        },
        onRegisterError: (error) => {
          if (import.meta.env.DEV) {
            console.error('[pwa] service worker registration failed', error)
          }
        },
      })
    }

    void register()

    return () => {
      isMounted = false
    }
  }, [])
}
