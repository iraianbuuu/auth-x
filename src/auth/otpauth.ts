import { decodeBase32, encodeBase32 } from "./base32.ts";
import { OtpError } from "./errors.ts";
import {
  DEFAULTS,
  type HashAlgorithm,
  resolveOptions,
  type TotpOptions,
} from "./types.ts";

export interface OtpAuthParams {
  /** Base32 secret, for example from `generateSecret`. */
  secret: string;
  /** The user's account name shown in the authenticator app, such as an email. */
  account: string;
  /** The service name shown in the authenticator app. */
  issuer?: string;
  /** TOTP settings; only values that differ from {@link DEFAULTS} are written. */
  options?: Partial<TotpOptions>;
}

export type ParsedOtpAuth = Omit<OtpAuthParams, "options"> & {
  options: TotpOptions;
};

const OPTION_NAMES = ["algorithm", "digits", "period"] as const;

function invalidUri(message: string): OtpError {
  return new OtpError("INVALID_URI", message);
}

/**
 * Builds the `otpauth://totp/...` URI that authenticator apps read from a QR
 * code.
 *
 * @throws {OtpError} `INVALID_SECRET` for a bad secret; `INVALID_OPTIONS` for
 * bad options; `INVALID_URI` if the account is empty or the issuer or account
 * contains `:`.
 */
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

/**
 * Parses an `otpauth://totp/...` URI. The returned options are complete, with
 * defaults filled in. The issuer comes from the `issuer` parameter or, if that
 * is missing, the label prefix.
 *
 * @throws {OtpError} `INVALID_URI` for a malformed URI, `INVALID_SECRET` for
 * a bad secret, `INVALID_OPTIONS` for bad options.
 */
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
