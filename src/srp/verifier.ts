import { modPow } from "../math";
import { SRPParameterSet, defaultParameters } from "../constants";
import { byteArrayToBigInt, hexStringToByteArray } from "../utils";

export type DigestFn = (options: {
  salt: Uint8Array;
  input: Uint8Array;
}) => Uint8Array | Promise<Uint8Array>;
export const digestPBKDF2 = async ({
  salt,
  input,
}: {
  salt: Uint8Array;
  input: Uint8Array;
}) => {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    input,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const hash = await crypto.subtle.deriveBits(
    // See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
    { name: "PBKDF2", iterations: 600_000, salt, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(hash);
};

const defaultSaltLength = 16;
export async function deriveVerifier(
  { username, password }: { username: string; password: string },
  {
    parameters = defaultParameters,
    digest = digestPBKDF2,
    ...options
  }: ({ salt: Uint8Array } | { saltLength?: number }) & {
    parameters?: SRPParameterSet;
    digest?: DigestFn;
  } = {}
): Promise<{ salt: Uint8Array; x: Uint8Array; verifier: Uint8Array }> {
  const salt =
    "salt" in options
      ? options.salt
      : new Uint8Array(options.saltLength ?? defaultSaltLength);

  const hashInput = new TextEncoder().encode([username, password].join(":"));
  const passwordHash = await digest({ input: hashInput, salt });

  const x = byteArrayToBigInt(passwordHash);
  const modulo = byteArrayToBigInt(parameters.N);
  const generator = byteArrayToBigInt(parameters.G);
  const verifier = modPow(generator, x, modulo);
  return {
    salt,
    x: passwordHash,
    verifier: hexStringToByteArray(verifier.toString(16).padStart(2, "0")),
  };
}
