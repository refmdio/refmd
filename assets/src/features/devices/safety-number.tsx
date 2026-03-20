import { createResource, For, Show } from "solid-js";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface Props {
  identitySigningPublic: Uint8Array;
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
  class?: string;
}

export function SafetyNumber(props: Props) {
  const [sas] = createResource(
    () => ({
      identitySigningPublic: props.identitySigningPublic,
      deviceSigningPublic: props.deviceSigningPublic,
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
