const HEADER = "RefMD Recovery Key";
const WORD_COUNT = 24;

export function formatRecoveryKeyFile(mnemonic: string): string {
  const words = mnemonic.split(" ");
  return [
    HEADER,
    "==================",
    "",
    "Keep this file in a safe place.",
    "You will need these 24 words to recover your account if you forget your password.",
    "",
    ...words.map((word, i) => `${String(i + 1).padStart(2, " ")}. ${word}`),
    "",
    "WARNING: If you lose this recovery key and forget your password,",
    "you will permanently lose access to your encrypted data.",
  ].join("\n");
}

export interface RecoveryKeyParseSuccess {
  words: string[];
}

export interface RecoveryKeyParseError {
  error: string;
}

export function parseRecoveryKeyFile(
  content: string,
): RecoveryKeyParseSuccess | RecoveryKeyParseError {
  const lines = content.split("\n");

  const hasHeader = lines.some((line) => line.includes(HEADER));
  if (!hasHeader) {
    return {
      error: "File format not recognized. Please upload a RefMD recovery key file.",
    };
  }

  const words: (string | null)[] = Array(WORD_COUNT).fill(null);

  for (const line of lines) {
    const match = line.match(/^\s*(\d+)\.\s+([a-z]+)\s*$/i);
    if (match) {
      const num = parseInt(match[1], 10);
      const word = match[2].toLowerCase();

      if (num >= 1 && num <= WORD_COUNT) {
        if (words[num - 1] !== null) {
          return { error: `Duplicate entry for word ${num}.` };
        }
        words[num - 1] = word;
      }
    }
  }

  const missingIndices = words
    .map((w, i) => (w === null ? i + 1 : null))
    .filter((i): i is number => i !== null);

  if (missingIndices.length > 0) {
    if (missingIndices.length === WORD_COUNT) {
      return { error: "No recovery words found in file." };
    }
    return {
      error: `Missing word(s) at position: ${missingIndices.join(", ")}.`,
    };
  }

  return { words: words as string[] };
}
