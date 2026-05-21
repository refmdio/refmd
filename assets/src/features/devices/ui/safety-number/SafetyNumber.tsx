import { createResource, For, Show } from "solid-js";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

interface Props {
  deviceId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
  class?: string;
}

export function SafetyNumber(props: Props) {
  const [sas] = createResource(
    () => ({
      deviceId: props.deviceId,
      identityHybridSigningPublicKeyMaterial: props.identityHybridSigningPublicKeyMaterial,
      deviceHybridSigningPublicKeyMaterial: props.deviceHybridSigningPublicKeyMaterial,
      deviceHybridEncryptionPublicKeyMaterial: props.deviceHybridEncryptionPublicKeyMaterial,
      deviceEcdhPublic: props.deviceEcdhPublic,
      clientNonce: props.clientNonce,
    }),
    async (params) => {
      const worker = getCryptoWorker();
      return worker.computeSas(params);
    },
  );

  return (
    <Show when={sas()}>
      {(sasData) => (
        <div
          class={`flex items-center justify-center gap-2 select-none ${props.class ?? ""}`}
          aria-label="Safety number"
        >
          <For each={sasData().emojis}>
            {(emoji) => (
              <span class="text-3xl" role="img">
                {emoji.emoji}
              </span>
            )}
          </For>
        </div>
      )}
    </Show>
  );
}
