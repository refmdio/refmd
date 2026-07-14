export function getDeviceName(userAgent = navigator.userAgent): string {
  if (/Chrome/.test(userAgent)) return "Chrome";
  if (/Firefox/.test(userAgent)) return "Firefox";
  if (/Safari/.test(userAgent)) return "Safari";
  return "Browser";
}

export function getDeviceType(userAgent = navigator.userAgent): "mobile" | "desktop" {
  if (/Mobi|Android/i.test(userAgent)) return "mobile";
  return "desktop";
}
