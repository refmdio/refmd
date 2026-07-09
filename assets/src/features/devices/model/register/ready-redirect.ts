interface ReadyDeviceRedirectInput {
  authPresent: boolean;
  needsPasswordReentry: boolean;
  hasDeviceId: boolean;
  cryptoWorkerReady: boolean;
  readyRedirectSuppressed: boolean;
  oauthRecoveryMnemonic: string | null;
}

export function shouldAutoRedirectReadyDevice(input: ReadyDeviceRedirectInput): boolean {
  if (!input.authPresent) return false;
  if (input.readyRedirectSuppressed || input.oauthRecoveryMnemonic) return false;
  return input.needsPasswordReentry || (input.hasDeviceId && input.cryptoWorkerReady);
}
