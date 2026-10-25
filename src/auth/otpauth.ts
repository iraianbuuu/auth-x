import { decodeBase32, encodeBase32 } from "./base32.ts";
import { OtpError } from "./errors.ts";
import {
  DEFAULTS,
  type HashAlgorithm,
  resolveOptions,
  type TotpOptions,
} from "./types.ts";

export interface OtpAuthParams {
  secret: string;
  account: string;
  issuer?: string;
  options?: Partial<TotpOptions>;
}

export type ParsedOtpAuth = Omit<OtpAuthParams, "options"> & {
  options: TotpOptions;
};

const OPTION_NAMES = ["algorithm", "digits", "period"] as const;

function invalidUri(message: string): OtpError {
  return new OtpError("INVALID_URI", message);
}

export function createOtpAuthUri({
  secret,
  account,
  issuer,
  options = {},
}: OtpAuthParams): string {
  const resolved = resolveOptions(options);
  const canonicalSecret = encodeBase32(decodeBase32(secret));

  if (!account) throw invalidUri("Account must not be empty");
  // The label uses ":" to separate issuer and account.
  if (account.includes(":") || issuer?.includes(":")) {
    throw invalidUri("Issuer and account must not contain a colon");
  }

  const label = encodeURIComponent(issuer ? `${issuer}:${account}` : account);
  let query = `secret=${canonicalSecret}`;
  if (issuer) query += `&issuer=${encodeURIComponent(issuer)}`;
  for (const name of OPTION_NAMES) {
    if (resolved[name] !== DEFAULTS[name]) {
      query += `&${name}=${resolved[name]}`;
    }
  }

  return `otpauth://totp/${label}?${query}`;
}

export function parseOtpAuthUri(uri: string): ParsedOtpAuth {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw invalidUri("Invalid otpauth URI");
  }
  if (url.protocol !== "otpauth:" || url.hostname !== "totp") {
    throw invalidUri("Invalid otpauth URI");
  }

  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) throw invalidUri("Missing secret");
  decodeBase32(secret);

  let label: string;
  try {
    label = decodeURIComponent(url.pathname.slice(1));
  } catch {
    throw invalidUri("Invalid label encoding");
  }

  const separatorIndex = label.indexOf(":");
  const labelIssuer =
    separatorIndex === -1 ? undefined : label.slice(0, separatorIndex);
  const account = label.slice(separatorIndex + 1);
  if (!account) throw invalidUri("Missing account");

  const issuerParam = params.get("issuer") || undefined;
  if (labelIssuer && issuerParam && labelIssuer !== issuerParam) {
    throw invalidUri("Issuer mismatch");
  }
  const issuer = issuerParam ?? labelIssuer;

  const algorithm = params.get("algorithm");
  const digits = params.get("digits");
  const period = params.get("period");
  // resolveOptions validates the values, so the casts only satisfy the types.
  const options = resolveOptions({
    ...(algorithm !== null && { algorithm: algorithm as HashAlgorithm }),
    ...(digits !== null && { digits: Number(digits) as TotpOptions["digits"] }),
    ...(period !== null && { period: Number(period) }),
  });

  return issuer
    ? { secret, issuer, account, options }
    : { secret, account, options };
}
