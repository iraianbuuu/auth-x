import { decodeBase32 } from "./auth/base32.ts";
import { generateTotp } from "./auth/totp.ts";

const key = decodeBase32("QKBZYA7LSM4757HWRPCQTTIJNI4XTZAB");

const unixSeconds = Math.floor(Date.now() / 1000);

const otp = generateTotp(key, { timestamp: unixSeconds });

console.log("My OTP:", otp);
