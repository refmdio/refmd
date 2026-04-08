import { createEffect, createSignal, onCleanup, type Accessor } from "solid-js";
import type { DeviceInfo } from "@/shared/api/devices";
import { authState, setTofuErrors } from "@/entities/session";
import { verifyDeviceListTofu } from "../../lib/tofu-verification";

export function useDeviceTofuVerification(deviceList: Accessor<DeviceInfo[] | undefined>) {
  const [tofuHardFail, setTofuHardFail] = createSignal(false);
  const [tofuWarnings, setTofuWarnings] = createSignal<string[]>([]);
  let verificationRun = 0;

  createEffect(() => {
    const devices = deviceList();
    const auth = authState();
    const runId = ++verificationRun;

    if (!devices || !auth) {
      setTofuHardFail(false);
      setTofuWarnings([]);
      setTofuErrors([]);
      return;
    }

    void verifyDeviceListTofu({
      devices,
      userId: auth.user.id,
      identitySigningPublic: auth.identitySigningPublic,
    })
      .then((result) => {
        if (runId !== verificationRun) {
          return;
        }

        setTofuHardFail(result.hardFailMessage !== null);
        setTofuWarnings(result.warnings);
        setTofuErrors(result.hardFailMessage ? [result.hardFailMessage] : []);
      })
      .catch(() => {
        if (runId !== verificationRun) {
          return;
        }

        setTofuHardFail(false);
        setTofuWarnings([]);
        setTofuErrors([]);
      });
  });

  onCleanup(() => {
    verificationRun++;
  });

  return {
    tofuHardFail,
    tofuWarnings,
  };
}
