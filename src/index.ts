import { generateTotp } from "./auth/totp.ts";

const secret = Buffer.from("12345678901234567890");

const timestamps = [
  59,
  1111111109,
  1111111111,
  1234567890,
  2000000000,
  20000000000,
];

for (const timestamp of timestamps) {
  const otp = generateTotp(secret, timestamp);
  console.log(timestamp, otp);
}