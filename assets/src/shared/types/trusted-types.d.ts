declare global {
  interface TrustedTypePolicy {
    createHTML(input: string): string;
  }

  interface TrustedTypePolicyFactory {
    createPolicy(
      policyName: string,
      policyOptions: {
        createHTML?: (input: string) => string;
      },
    ): TrustedTypePolicy;
  }

  interface Window {
    trustedTypes?: TrustedTypePolicyFactory;
  }

  var trustedTypes: TrustedTypePolicyFactory | undefined;
}

export {};
