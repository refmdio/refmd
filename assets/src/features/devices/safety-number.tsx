import { createMemo, For } from "solid-js";
import { computeSas } from "@/shared/lib/crypto";

interface Props {
  identitySigningPublic: Uint8Array;
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
  class?: string;
}

export function SafetyNumber(props: Props) {
  const sas = createMemo(() =>
    computeSas(
      props.identitySigningPublic,
      props.deviceSigningPublic,
      props.deviceEcdhPublic,
      props.clientNonce,
    ),
  );

  return (
    <div
      class={`flex items-center justify-center gap-2 select-none ${props.class ?? ""}`}
      aria-label="Safety number"
    >
      <For each={sas().emojis}>
        {(emoji) => (
          <span class="text-3xl" role="img">
            {emoji}
          </span>
        )}
      </For>
    </div>
  );
}
