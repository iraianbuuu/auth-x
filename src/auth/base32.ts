import { OtpError } from "./errors.ts";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(input: string): Buffer {
  const cleaned = input.replace(/\s/g, "").replace(/=+$/, "").toUpperCase();

  let bitstream = "";
  for (const char of cleaned) {
    const value = ALPHABET.indexOf(char);

    if (value === -1) {
      throw new OtpError("INVALID_SECRET", `Invalid Base32 character: ${char}`);
    }
    bitstream += value.toString(2).padStart(5, "0");
  }

  const leftover = bitstream.length % 8;
  if (leftover >= 5) {
    throw new OtpError("INVALID_SECRET", "Invalid Base32 length");
  }
  if (bitstream.slice(bitstream.length - leftover).includes("1")) {
    throw new OtpError("INVALID_SECRET", "Invalid Base32 padding bits");
  }

  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bitstream.length; i += 8) {
    const chunk = bitstream.substring(i, i + 8);
    bytes.push(Number.parseInt(chunk, 2));
  }

  return Buffer.from(bytes);
}

export function encodeBase32(input: Buffer): string {
  let bitstream = "";

  for (const byte of input) {
    bitstream += byte.toString(2).padStart(8, "0");
  }

  let result = "";
  for (let i = 0; i < bitstream.length; i += 5) {
    const chunk = bitstream.substring(i, i + 5).padEnd(5, "0");
    result += ALPHABET[Number.parseInt(chunk, 2)];
  }

  return result;
}
