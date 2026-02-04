/**
 * Device detection utilities
 *
 * Shared functions for detecting device type and generating device names
 * based on user agent information.
 */

export type DeviceType = 'browser' | 'desktop' | 'mobile'

/**
 * Detect device type from user agent
 */
export function detectDeviceType(): DeviceType {
  if (typeof window === 'undefined') return 'browser'

  const ua = navigator.userAgent.toLowerCase()

  // Check for mobile devices
  if (/android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini|mobile/i.test(ua)) {
    return 'mobile'
  }

  // Check for Electron or similar desktop apps
  if (/electron/i.test(ua)) {
    return 'desktop'
  }

  // Default to browser
  return 'browser'
}

/**
 * Generate a descriptive device name based on browser and OS
 */
export function detectDeviceName(): string {
  if (typeof window === 'undefined') return 'Unknown Device'

  const ua = navigator.userAgent

  // Detect browser (order matters - Edge includes Chrome in UA)
  let browser = 'Browser'
  if (ua.includes('Edg')) browser = 'Edge'
  else if (ua.includes('Firefox')) browser = 'Firefox'
  else if (ua.includes('Opera') || ua.includes('OPR')) browser = 'Opera'
  else if (ua.includes('Chrome')) browser = 'Chrome'
  else if (ua.includes('Safari')) browser = 'Safari'

  // Detect OS (order matters - iPhone/iPad UA contains "Mac OS X")
  let os = ''
  if (ua.includes('iPhone') || ua.includes('iPad') || ua.includes('iPod')) os = 'iOS'
  else if (ua.includes('Android')) os = 'Android'
  else if (ua.includes('Windows')) os = 'Windows'
  else if (ua.includes('Mac')) os = 'macOS'
  else if (ua.includes('Linux')) os = 'Linux'

  return os ? `${browser} on ${os}` : browser
}
