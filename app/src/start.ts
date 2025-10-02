import { createStart } from '@tanstack/react-start'

import { authMiddleware } from '@/middleware'

export const startInstance = createStart(() => ({
  requestMiddleware: [authMiddleware],
}))
