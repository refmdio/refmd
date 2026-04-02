export type DeviceRegistrationPhase =
  | "generating"
  | "waiting"
  | "restoring"
  | "done"
  | "error"
  | "expired"
  | "needs_password"
  | "reauth";

export interface DeviceRegistrationPublicKeys {
  ecdhPublic: Uint8Array;
  signingPublic: Uint8Array;
}
