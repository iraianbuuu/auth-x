import { randomBytes } from "node:crypto";
import {
  createEnrollment,
  decodeBase32,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateTotp,
  verifyRecoveryCode,
  verifyTotp,
} from "@/index.ts";

// In a real app the keys come from a secrets manager, not randomBytes.
const keyring = { current: "2026-10", keys: { "2026-10": randomBytes(32) } };

const { secret, uri } = createEnrollment({
  account: "alice@example.com",
  issuer: "auth-x demo",
});
const storedSecret = encryptSecret(secret, keyring, "user:alice");
const { codes, hashes } = generateRecoveryCodes();
console.log("Render this URI as a QR code:", uri);
console.log("Stored secret:", storedSecret);

const key = decodeBase32(decryptSecret(storedSecret, keyring, "user:alice"));
const code = generateTotp(key);
const step = verifyTotp(key, code);
console.log(`Code ${code} verified at step ${step}`);
console.log(
  "Same code again:",
  verifyTotp(key, code, { afterStep: step ?? -1 }),
);

console.log(
  `Recovery code ${codes[0]} matches hash`,
  verifyRecoveryCode(codes[0] ?? "", hashes),
);
