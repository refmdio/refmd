export class TrustTransferKeyVerificationError extends Error {
  constructor() {
    super("Trust state sender key verification failed");
    this.name = "TrustTransferKeyVerificationError";
  }
}
