export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(str: string): Uint8Array {
  if (/[+/=\s]/.test(str)) {
    throw new Error("Invalid base64url: contains standard base64 characters");
  }
  if (str.length % 4 === 1) {
    throw new Error("Invalid base64url: invalid length");
  }
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const paddedWithEquals = padded + "====".slice(padded.length % 4 || 4);
  const binary = atob(paddedWithEquals);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

export function randomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}
