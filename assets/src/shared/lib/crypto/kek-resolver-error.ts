export class KekResolutionError extends Error {
  readonly workspaceId: string;

  constructor(workspaceId: string, message: string) {
    super(message);
    this.name = "KekResolutionError";
    this.workspaceId = workspaceId;
  }
}
