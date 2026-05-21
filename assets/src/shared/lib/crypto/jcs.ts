export type StrictJsonValue =
  | string
  | number
  | boolean
  | StrictJsonValue[]
  | { readonly [key: string]: StrictJsonValue };

const MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991;
const encoder = new TextEncoder();

export function canonicalizeStrictBytes(value: StrictJsonValue): Uint8Array {
  return encoder.encode(canonicalizeStrict(value));
}

export function canonicalizeStrict(value: StrictJsonValue): string {
  if (!isPlainObject(value)) {
    throw new Error("jcs_root_must_be_object");
  }
  return canonicalizeValue(value);
}

export function parseJsonStrict(raw: string): StrictJsonValue {
  const parser = new StrictJsonParser(raw);
  return parser.parse();
}

export function parseJsonStrictBytes(raw: Uint8Array): StrictJsonValue {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  return parseJsonStrict(decoded);
}

function canonicalizeValue(value: StrictJsonValue): string {
  if (typeof value === "string") return quoteString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return canonicalizeInteger(value);
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) throw new Error("jcs_sparse_array_rejected");
      items.push(canonicalizeValue(value[i]!));
    }
    return `[${items.join(",")}]`;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort(compareUtf8);
    return `{${keys
      .map((key) => {
        const item = value[key];
        if (item === undefined) throw new Error("jcs_undefined_rejected");
        return `${quoteString(key)}:${canonicalizeValue(item)}`;
      })
      .join(",")}}`;
  }
  throw new Error("jcs_unsupported_value");
}

function canonicalizeInteger(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("jcs_invalid_integer");
  }
  return String(value);
}

function isPlainObject(value: unknown): value is { readonly [key: string]: StrictJsonValue } {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

export function compareUtf8(a: string, b: string): number {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.min(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const diff = left[i]! - right[i]!;
    if (diff !== 0) return diff;
  }
  return left.length - right.length;
}

function quoteString(value: string): string {
  assertValidUnicodeScalarString(value);
  return JSON.stringify(value);
}

function assertValidUnicodeScalarString(value: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        throw new Error("jcs_invalid_unicode");
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("jcs_invalid_unicode");
    }
  }
}

class StrictJsonParser {
  private index = 0;
  private readonly raw: string;

  constructor(raw: string) {
    this.raw = raw;
  }

  parse(): StrictJsonValue {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.raw.length) throw new Error("json_trailing_data");
    if (!isPlainObject(value)) throw new Error("jcs_root_must_be_object");
    return value;
  }

  private parseValue(): StrictJsonValue {
    this.skipWhitespace();
    const char = this.peek();
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseLiteral("true", true);
    if (char === "f") return this.parseLiteral("false", false);
    if (char === "n") throw new Error("jcs_null_rejected");
    if (char >= "0" && char <= "9") return this.parseInteger();
    if (char === "-") throw new Error("jcs_negative_integer_rejected");
    throw new Error("json_unexpected_token");
  }

  private parseObject(): StrictJsonValue {
    this.consume("{");
    const result: Record<string, StrictJsonValue> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.peek() === "}") {
      this.consume("}");
      return result;
    }
    while (true) {
      this.skipWhitespace();
      const key = this.parseString();
      if (seen.has(key)) throw new Error("json_duplicate_key");
      seen.add(key);
      this.skipWhitespace();
      this.consume(":");
      result[key] = this.parseValue();
      this.skipWhitespace();
      if (this.peek() === "}") {
        this.consume("}");
        return result;
      }
      this.consume(",");
    }
  }

  private parseArray(): StrictJsonValue[] {
    this.consume("[");
    const result: StrictJsonValue[] = [];
    this.skipWhitespace();
    if (this.peek() === "]") {
      this.consume("]");
      return result;
    }
    while (true) {
      result.push(this.parseValue());
      this.skipWhitespace();
      if (this.peek() === "]") {
        this.consume("]");
        return result;
      }
      this.consume(",");
    }
  }

  private parseString(): string {
    this.consume('"');
    let out = "";
    while (this.index < this.raw.length) {
      const char = this.raw[this.index++]!;
      if (char === '"') {
        assertValidUnicodeScalarString(out);
        return out;
      }
      if (char === "\\") {
        out += this.parseEscape();
        continue;
      }
      if (char.charCodeAt(0) <= 0x1f) throw new Error("json_unescaped_control");
      out += char;
    }
    throw new Error("json_unterminated_string");
  }

  private parseEscape(): string {
    const esc = this.raw[this.index++]!;
    if (esc === '"' || esc === "\\" || esc === "/") return esc;
    if (esc === "b") return "\b";
    if (esc === "f") return "\f";
    if (esc === "n") return "\n";
    if (esc === "r") return "\r";
    if (esc === "t") return "\t";
    if (esc !== "u") throw new Error("json_invalid_escape");
    const code = this.parseHex4();
    if (code >= 0xd800 && code <= 0xdbff) {
      if (this.raw[this.index] !== "\\" || this.raw[this.index + 1] !== "u") {
        throw new Error("jcs_invalid_unicode");
      }
      this.index += 2;
      const low = this.parseHex4();
      if (low < 0xdc00 || low > 0xdfff) throw new Error("jcs_invalid_unicode");
      return String.fromCharCode(code, low);
    }
    if (code >= 0xdc00 && code <= 0xdfff) throw new Error("jcs_invalid_unicode");
    return String.fromCharCode(code);
  }

  private parseHex4(): number {
    const hex = this.raw.slice(this.index, this.index + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error("json_invalid_unicode_escape");
    this.index += 4;
    return Number.parseInt(hex, 16);
  }

  private parseInteger(): number {
    const start = this.index;
    if (this.peek() === "0") {
      this.index += 1;
      if (/[0-9]/.test(this.peek())) throw new Error("json_invalid_integer");
    } else {
      while (/[0-9]/.test(this.peek())) this.index += 1;
    }
    if (this.peek() === "." || this.peek() === "e" || this.peek() === "E") {
      throw new Error("json_invalid_number_form");
    }
    const value = Number(this.raw.slice(start, this.index));
    if (!Number.isSafeInteger(value) || value > MAX_SAFE_JSON_INTEGER) {
      throw new Error("jcs_invalid_integer");
    }
    return value;
  }

  private parseLiteral<T extends boolean>(literal: string, value: T): T {
    if (this.raw.slice(this.index, this.index + literal.length) !== literal) {
      throw new Error("json_invalid_literal");
    }
    this.index += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (/[\t\n\r ]/.test(this.peek())) this.index += 1;
  }

  private consume(expected: string): void {
    if (this.raw[this.index] !== expected) throw new Error("json_unexpected_token");
    this.index += 1;
  }

  private peek(): string {
    return this.raw[this.index] ?? "";
  }
}
