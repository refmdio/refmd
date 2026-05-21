import { parseRecoveryKeyFile } from "@/shared/lib/recovery/key-format";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

const WORD_COUNT = 24;
const MAX_FILE_SIZE = 10 * 1024;

export function createEmptyWords(): string[] {
  return Array(WORD_COUNT).fill("");
}

export function applyWordChange(
  currentWords: string[],
  index: number,
  value: string,
): { words: string[]; focusIndex: number | null } {
  if (value.includes(" ") && index === 0) {
    const pasted = value.trim().toLowerCase().split(/\s+/);
    if (pasted.length === WORD_COUNT) {
      return { words: pasted, focusIndex: WORD_COUNT - 1 };
    }
  }

  const words = [...currentWords];
  words[index] = value.toLowerCase().trim();
  return {
    words,
    focusIndex: value && index < WORD_COUNT - 1 ? index + 1 : null,
  };
}

export function getWordFocusTarget(
  currentWords: string[],
  index: number,
  event: KeyboardEvent,
): number | null {
  if (event.key === "ArrowRight" && index < WORD_COUNT - 1) {
    return index + 1;
  }
  if (event.key === "ArrowLeft" && index > 0) {
    return index - 1;
  }
  if (event.key === "ArrowUp") {
    const target = index - 4;
    return target >= 0 ? target : null;
  }
  if (event.key === "ArrowDown") {
    const target = index + 4;
    return target < WORD_COUNT ? target : null;
  }
  if (event.key === "Backspace" && !currentWords[index] && index > 0) {
    return index - 1;
  }
  return null;
}

export async function readWordsFromFile(
  file: File,
): Promise<{ words: string[] } | { error: string }> {
  if (file.size > MAX_FILE_SIZE) {
    return {
      error: "File is too large. Recovery key files should be less than 10KB.",
    };
  }

  try {
    const content = await file.text();
    const result = parseRecoveryKeyFile(content);

    if ("error" in result) {
      return { error: result.error };
    }

    const mnemonic = result.words.join(" ");
    if (!(await getCryptoWorker().validateMnemonic(mnemonic))) {
      return {
        error: "Invalid recovery key file: contains invalid BIP39 words.",
      };
    }

    return { words: result.words };
  } catch {
    return { error: "Failed to read file." };
  }
}
