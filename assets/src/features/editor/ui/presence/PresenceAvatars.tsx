import { createSignal, createEffect, onCleanup, Show, For } from "solid-js";
import type { Awareness } from "y-protocols/awareness";

interface AwarenessUser {
  userId?: string;
  name?: string;
  color?: string;
  signingKeyId?: string;
}

interface RemoteUser {
  clientId: number;
  name: string;
  color: string;
  sameUser: boolean;
}

export function PresenceAvatars(props: { awareness: Awareness | null }) {
  const [remoteUsers, setRemoteUsers] = createSignal<RemoteUser[]>([]);

  createEffect(() => {
    const awareness = props.awareness;
    if (!awareness) {
      setRemoteUsers([]);
      return;
    }

    const update = () => {
      const localId = awareness.clientID;
      const localState = awareness.getLocalState();
      const localUserId = (localState?.user as AwarenessUser | undefined)?.userId;

      const users: RemoteUser[] = [];
      awareness.getStates().forEach((state, clientId) => {
        if (clientId === localId) return;
        const user = state.user as AwarenessUser | undefined;
        if (!user?.name) return;

        const isSameUser = !!(localUserId && user.userId === localUserId);

        users.push({
          clientId,
          name: user.name,
          color: user.color ?? "#888",
          sameUser: isSameUser,
        });
      });
      setRemoteUsers(users);
    };

    update();
    awareness.on("change", update);
    onCleanup(() => awareness.off("change", update));
  });

  return (
    <Show when={remoteUsers().length > 0}>
      <div class="flex items-center gap-0.5 mr-1">
        <For each={remoteUsers()}>
          {(user) => (
            <div class="relative" title={user.sameUser ? `${user.name} (other device)` : user.name}>
              <div
                class="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-medium cursor-default"
                classList={{
                  "text-white": !user.sameUser,
                  "text-white/70 ring-1 ring-dashed ring-white/40": user.sameUser,
                }}
                style={{
                  "background-color": user.sameUser ? `${user.color}80` : user.color,
                }}
              >
                {user.name.charAt(0).toUpperCase()}
              </div>
              <Show when={user.sameUser}>
                <span class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-muted border border-border" />
              </Show>
            </div>
          )}
        </For>
      </div>
    </Show>
  );
}
