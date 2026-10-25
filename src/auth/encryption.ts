import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { OtpError } from "./errors.ts";

const VERSION = "v1";
const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;

export interface Keyring {
  // ID of the key that encrypts new payloads.
  current: string;
  // Every key that may still be needed to decrypt existing payloads.
  keys: Record<string, Buffer>;
}

function decryptionFailed(message = "Could not decrypt the secret"): OtpError {
  return new OtpError("DECRYPTION_FAILED", message);
}

function checkKey(key: Buffer | undefined, id: string): Buffer {
  if (key?.length !== KEY_BYTES) {
    throw new OtpError(
      "INVALID_KEY",
      `Key "${id}" must be a ${KEY_BYTES}-byte Buffer`,
    );
  }
  return key;
}

// The version and key ID are authenticated along with the caller's context,
// so editing either one in a stored payload makes decryption fail. `context`
// binds the payload to one owner (for example a user ID), so a payload copied
// to another user's row fails to decrypt there.
function additionalData(keyId: string, context: string): Buffer {
  return Buffer.from(`${VERSION}:${keyId}:${context}`);
}

export function encryptSecret(
  secret: string,
  keyring: Keyring,
  context = "",
): string {
  const keyId = keyring.current;
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new OtpError(
      "INVALID_KEY",
      "Key ID must be 1 to 32 letters, digits, dashes or underscores",
    );
  }
  const key = checkKey(keyring.keys[keyId], keyId);
  if (!secret) throw new OtpError("INVALID_SECRET", "Secret must not be empty");

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(additionalData(keyId, context));
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    VERSION,
    keyId,
    ...[iv, tag, ciphertext].map((b) => b.toString("base64")),
  ].join(":");
}

export function decryptSecret(
  payload: string,
  keyring: Keyring,
  context = "",
): string {
  const parts = payload.split(":");
  const [version, keyId = ""] = parts;
  if (
    parts.length !== 5 ||
    version !== VERSION ||
    !KEY_ID_PATTERN.test(keyId)
  ) {
    throw decryptionFailed();
  }
  if (!Object.hasOwn(keyring.keys, keyId)) {
    throw decryptionFailed(`Key "${keyId}" is not in the keyring`);
  }
  const key = checkKey(keyring.keys[keyId], keyId);

  const [iv, tag, ciphertext] = parts
    .slice(2)
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
    decipher.setAAD(additionalData(keyId, context));
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

// True when the payload was encrypted with a key other than keyring.current,
// so the caller should decrypt it and encrypt it again during key rotation.
export function needsReencryption(payload: string, keyring: Keyring): boolean {
  return payload.split(":")[1] !== keyring.current;
}
