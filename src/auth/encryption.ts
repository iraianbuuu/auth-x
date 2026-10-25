import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { OtpError } from "./errors.ts";

const VERSION = "v1";
const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

function checkKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) {
    throw new OtpError(
      "INVALID_KEY",
      `Encryption key must be ${KEY_BYTES} bytes`,
    );
  }
}

function decryptionFailed(): OtpError {
  return new OtpError("DECRYPTION_FAILED", "Could not decrypt the secret");
}

// `context` is bound to the payload as additional authenticated data, so a
// payload copied to another user's row fails to decrypt there.
export function encryptSecret(
  secret: string,
  key: Buffer,
  context = "",
): string {
  checkKey(key);
  if (!secret) throw new OtpError("INVALID_SECRET", "Secret must not be empty");

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [VERSION, iv, tag, ciphertext]
    .map((part) => (typeof part === "string" ? part : part.toString("base64")))
    .join(":");
}

export function decryptSecret(
  payload: string,
  key: Buffer,
  context = "",
): string {
  checkKey(key);

  const parts = payload.split(":");
  if (parts.length !== 4 || parts[0] !== VERSION) throw decryptionFailed();
  const [iv, tag, ciphertext] = parts
    .slice(1)
    .map((part) => Buffer.from(part, "base64"));
  if (
    iv?.length !== IV_BYTES ||
    tag?.length !== TAG_BYTES ||
    !ciphertext?.length
  ) {
    throw decryptionFailed();
  }

  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(tag);
    // final() throws when the tag does not match: wrong key, wrong context
    // or changed bytes.
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString();
  } catch {
    throw decryptionFailed();
  }
}
