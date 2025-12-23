import { useEffect } from 'react'

export function useServiceWorker() {
  useEffect(() => {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
      return
    }

    const enableInDev = import.meta.env.VITE_PWA_DEV === 'true'
    const shouldRegister = import.meta.env.PROD || enableInDev

    let isMounted = true

    const register = async () => {
      if (!shouldRegister) {
        if (import.meta.env.DEV) {
          try {
            const registrations = await navigator.serviceWorker.getRegistrations()
            await Promise.all(registrations.map((registration) => registration.unregister()))
          } catch {
            /* noop */
          }
          try {
            if ('caches' in window) {
              const keys = await window.caches.keys()
              await Promise.all(keys.map((key) => window.caches.delete(key)))
            }
          } catch {
            /* noop */
          }
        }
        return
      }

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
