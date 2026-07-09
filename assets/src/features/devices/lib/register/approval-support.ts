import { devicesApi } from "@/shared/api";

export async function retryGetUmk(
  deviceId: string,
  maxAttempts: number,
  delayMs: number,
  rrpDeviceId?: string,
): Promise<Awaited<ReturnType<typeof devicesApi.getUmk>>> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await devicesApi.getUmk(deviceId, rrpDeviceId ? { rrpDeviceId } : undefined);
    } catch (error) {
      if (attempt === maxAttempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  throw new Error("UMK retrieval failed after retries");
}
