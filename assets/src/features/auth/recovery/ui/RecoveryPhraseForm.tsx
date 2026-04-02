import { For, Show } from "solid-js";
import { AlertTriangleIcon, UploadIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";

interface RecoveryPhraseFormProps {
  words: string[];
  loading: boolean;
  error: string | null;
  isPasswordReset: boolean;
  showTryAgain: boolean;
  onFileUpload: (event: Event) => Promise<void>;
  onWordChange: (index: number, value: string, focusWord: (index: number) => void) => void;
  onWordKeyDown: (index: number, event: KeyboardEvent, focusWord: (index: number) => void) => void;
  onSubmit: (event: Event) => Promise<void>;
  onClear: () => void;
  onTryAgain: () => void;
}

export function RecoveryPhraseForm(props: RecoveryPhraseFormProps) {
  const inputRefs: (HTMLInputElement | undefined)[] = [];
  let fileInputRef: HTMLInputElement | undefined;

  const focusWord = (index: number) => {
    inputRefs[index]?.focus();
  };

  return (
    <>
      <form onSubmit={props.onSubmit} class="space-y-6">
        <Show when={props.error}>
          {(currentError) => (
            <Alert variant="destructive">
              <AlertTriangleIcon />
              <AlertDescription>{currentError()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <FieldLabel>Recovery Phrase</FieldLabel>
            <Button type="button" variant="outline" size="sm" onClick={() => fileInputRef?.click()}>
              <UploadIcon class="size-3 mr-1" />
              Upload File
            </Button>
            <input
              ref={(element) => {
                fileInputRef = element;
              }}
              type="file"
              accept=".txt"
              onChange={props.onFileUpload}
              class="hidden"
            />
          </div>
          <p class="text-xs text-muted-foreground mb-4">
            Upload your recovery key file or enter each word manually. You can also paste the full
            24-word phrase into the first field.
          </p>

          <div class="grid grid-cols-4 gap-2">
            <For each={props.words}>
              {(word, index) => (
                <div class="flex items-center gap-1">
                  <span class="text-xs text-muted-foreground w-5 text-right">{index() + 1}.</span>
                  <Input
                    ref={(element) => {
                      inputRefs[index()] = element;
                    }}
                    type="text"
                    value={word}
                    onInput={(inputEvent) =>
                      props.onWordChange(index(), inputEvent.currentTarget.value, focusWord)
                    }
                    onKeyDown={(keyboardEvent) =>
                      props.onWordKeyDown(index(), keyboardEvent, focusWord)
                    }
                    placeholder="word"
                    class="h-8 text-sm font-mono"
                    autocomplete="off"
                    autocorrect="off"
                    autocapitalize="off"
                    spellcheck={false}
                    disabled={props.loading}
                  />
                </div>
              )}
            </For>
          </div>
        </div>

        <div class="flex gap-2">
          <Button type="submit" class="flex-1" disabled={props.loading}>
            {props.loading ? (
              <span class="flex items-center gap-2">
                <Spinner class="size-3" /> Recovering...
              </span>
            ) : props.isPasswordReset ? (
              "Verify Recovery Phrase"
            ) : (
              "Recover Account"
            )}
          </Button>
          <Show when={props.showTryAgain}>
            <Button type="button" variant="outline" onClick={props.onTryAgain}>
              Try Again
            </Button>
          </Show>
          <Show when={!props.showTryAgain}>
            <Button type="button" variant="outline" onClick={props.onClear}>
              Clear
            </Button>
          </Show>
        </div>

        <div class="text-center">
          <a href="/auth/login" class="text-sm text-muted-foreground hover:text-primary underline">
            Back to Login
          </a>
        </div>
      </form>

      <div class="mt-6 p-4 bg-muted rounded-lg">
        <h4 class="font-semibold text-sm mb-2">Important Security Notes</h4>
        <ul class="text-xs text-muted-foreground space-y-1">
          <li>Never share your recovery phrase with anyone</li>
          <li>RefMD staff will never ask for your recovery phrase</li>
          <li>Make sure you're on the official RefMD website</li>
          <li>Your recovery phrase proves you own the account</li>
        </ul>
      </div>
    </>
  );
}
