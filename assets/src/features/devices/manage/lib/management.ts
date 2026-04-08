import { devicesApi } from "@/shared/api";

export const DEVICES_QUERY_KEY = ["devices"] as const;

export async function listDevices() {
  return devicesApi.list();
}

export async function renameDevice(deviceId: string, name: string): Promise<void> {
  await devicesApi.rename(deviceId, name);
}
