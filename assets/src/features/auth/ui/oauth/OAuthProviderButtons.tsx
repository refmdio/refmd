import { For, Show } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import type { OAuthProvider } from "../../lib/oauth/oauth";

type OAuthProviderButtonsProps = {
  providers: OAuthProvider[];
  loadingProvider: OAuthProvider | null;
  disabled?: boolean;
  actionLabel?: string;
  onStart: (provider: OAuthProvider) => void;
};

export function OAuthProviderButtons(props: OAuthProviderButtonsProps) {
  const disabled = () => props.disabled === true || props.loadingProvider !== null;

  return (
    <div class="grid grid-cols-1 gap-2">
      <For each={props.providers}>
        {(provider) => {
          const label = providerLabel(provider);
          const buttonLabel = () => `${props.actionLabel ?? "Continue with"} ${label}`;
          const loading = () => props.loadingProvider === provider;

          return (
            <Button
              type="button"
              variant="outline"
              class="relative h-11 w-full justify-center px-4 font-sans text-sm font-medium normal-case tracking-normal"
              disabled={disabled()}
              aria-label={buttonLabel()}
              onClick={() => props.onStart(provider)}
            >
              <Show
                when={loading()}
                fallback={
                  <>
                    <ProviderIcon provider={provider} />
                    <span class="min-w-0 font-sans tracking-normal">{buttonLabel()}</span>
                  </>
                }
              >
                <span class="flex min-w-0 items-center justify-center gap-2">
                  <Spinner class="size-3 shrink-0" />
                  <span class="font-sans tracking-normal">{buttonLabel()}</span>
                </span>
              </Show>
            </Button>
          );
        }}
      </For>
    </div>
  );
}

export function providerLabel(provider: OAuthProvider): string {
  return provider === "google" ? "Google" : "GitHub";
}

export function ProviderIcon(props: { provider: OAuthProvider }) {
  if (props.provider === "google") {
    return (
      <svg
        aria-hidden="true"
        viewBox="0 0 18 18"
        class="size-5 shrink-0"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          fill="#4285F4"
          d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.91c1.7-1.57 2.69-3.88 2.69-6.62Z"
        />
        <path
          fill="#34A853"
          d="M9 18c2.43 0 4.47-.81 5.96-2.18l-2.91-2.26c-.81.54-1.84.86-3.05.86-2.35 0-4.33-1.58-5.04-3.71H.96v2.33A9 9 0 0 0 9 18Z"
        />
        <path
          fill="#FBBC05"
          d="M3.96 10.71A5.41 5.41 0 0 1 3.68 9c0-.59.1-1.17.28-1.71V4.96H.96A9 9 0 0 0 0 9c0 1.45.35 2.82.96 4.04l3-2.33Z"
        />
        <path
          fill="#EA4335"
          d="M9 3.58c1.32 0 2.51.45 3.44 1.35l2.58-2.58C13.46.89 11.43 0 9 0A9 9 0 0 0 .96 4.96l3 2.33C4.67 5.16 6.65 3.58 9 3.58Z"
        />
      </svg>
    );
  }

  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" class="size-5 shrink-0 fill-current">
      <path d="M10.226 17.284c-2.965-.36-5.054-2.493-5.054-5.256 0-1.123.404-2.336 1.078-3.144-.292-.741-.247-2.314.09-2.965.898-.112 2.111.36 2.83 1.01.853-.269 1.752-.404 2.853-.404 1.1 0 1.999.135 2.807.382.696-.629 1.932-1.1 2.83-.988.315.606.36 2.179.067 2.942.72.854 1.101 2 1.101 3.167 0 2.763-2.089 4.852-5.098 5.234.763.494 1.28 1.572 1.28 2.807v2.336c0 .674.561 1.056 1.235.786 4.066-1.55 7.255-5.615 7.255-10.646C23.5 6.188 18.334 1 11.978 1 5.62 1 .5 6.188.5 12.545c0 4.986 3.167 9.12 7.435 10.669.606.225 1.19-.18 1.19-.786V20.63a2.9 2.9 0 0 1-1.078.224c-1.483 0-2.359-.808-2.987-2.313-.247-.607-.517-.966-1.034-1.033-.27-.023-.359-.135-.359-.27 0-.27.45-.471.898-.471.652 0 1.213.404 1.797 1.235.45.651.921.943 1.483.943.561 0 .92-.202 1.437-.719.382-.381.674-.718.944-.943" />
    </svg>
  );
}
