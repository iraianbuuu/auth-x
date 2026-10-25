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

// In a real app this key comes from a secrets manager, not randomBytes.
const encryptionKey = randomBytes(32);

const { secret, uri } = await createEnrollment({
  account: "alice@example.com",
  issuer: "auth-x demo",
});
const storedSecret = encryptSecret(secret, encryptionKey, "user:alice");
const { codes, hashes } = generateRecoveryCodes();
console.log("Scan this URI:", uri);
console.log("Stored secret:", storedSecret);

const key = decodeBase32(
  decryptSecret(storedSecret, encryptionKey, "user:alice"),
);
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
