declare global {
  interface Window {
    trustedTypes?: TrustedTypePolicyFactory;
  }

  var trustedTypes: TrustedTypePolicyFactory | undefined;
}

export {};
