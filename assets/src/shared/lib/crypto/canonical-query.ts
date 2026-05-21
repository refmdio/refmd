const textEncoder = new TextEncoder();

export function canonicalQueryString(rawQuery: string): string {
  const query = rawQuery.startsWith("?") ? rawQuery.slice(1) : rawQuery;
  if (query.length === 0) return "";

  return query
    .split("&")
    .map(parseQueryPair)
    .sort(compareQueryPairs)
    .map(
      ([key, value]) => `${percentEncodeQueryComponent(key)}=${percentEncodeQueryComponent(value)}`,
    )
    .join("&");
}

function parseQueryPair(pair: string): [string, string] {
  const separatorIndex = pair.indexOf("=");
  if (separatorIndex === -1) return [decodeQueryComponent(pair), ""];
  return [
    decodeQueryComponent(pair.slice(0, separatorIndex)),
    decodeQueryComponent(pair.slice(separatorIndex + 1)),
  ];
}

function decodeQueryComponent(value: string): string {
  return decodeURIComponent(value.replace(/\+/g, " "));
}

function compareQueryPairs([keyA, valueA]: [string, string], [keyB, valueB]: [string, string]) {
  return compareUtf8Bytes(keyA, keyB) || compareUtf8Bytes(valueA, valueB);
}

function compareUtf8Bytes(left: string, right: string): number {
  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function percentEncodeQueryComponent(value: string): string {
  return [...textEncoder.encode(value)]
    .map((byte) => {
      if (isUnreserved(byte)) return String.fromCharCode(byte);
      return `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    })
    .join("");
}

function isUnreserved(byte: number): boolean {
  return (
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    (byte >= 0x30 && byte <= 0x39) ||
    byte === 0x2d ||
    byte === 0x2e ||
    byte === 0x5f ||
    byte === 0x7e
  );
}
