let transientPuk: Uint8Array | null = null;
let transientRuk: Uint8Array | null = null;
export function cloneTransientPuk(): Uint8Array | null {
  return transientPuk ? new Uint8Array(transientPuk) : null;
}
export function takeTransientPuk(): Uint8Array | null {
  const puk = transientPuk;
  transientPuk = null;
  return puk;
}
export function setTransientPuk(puk: Uint8Array): void {
  clearTransientPuk();
  transientPuk = puk;
}
export function clearTransientPuk(): void {
  if (transientPuk) {
    transientPuk.fill(0);
  }
  transientPuk = null;
}
export function takeTransientRuk(): Uint8Array | null {
  const ruk = transientRuk;
  transientRuk = null;
  return ruk;
}
export function setTransientRuk(ruk: Uint8Array): void {
  clearTransientRuk();
  transientRuk = ruk;
}
function clearTransientRuk(): void {
  if (transientRuk) {
    transientRuk.fill(0);
  }
  transientRuk = null;
}
export function clearTransientKeys(): void {
  clearTransientPuk();
  clearTransientRuk();
}
