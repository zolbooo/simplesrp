import { G, N } from "../constants";
import { modPow } from "../math";
import {
  concatByteArrays,
  bigIntToByteArray,
  byteArrayToBigInt,
  hexStringToByteArray,
  generateRandomExponent,
} from "../utils";

import { deriveSharedHash } from "./common";
import { DigestFn, deriveVerifier, digestPBKDF2 } from "./verifier";
import { DeriveMultiplierFn, deriveMultiplierSRP6a } from "./multiplier";

export function generateClientEphemeral({
  N: moduloBytes = N,
  G: generatorBytes = G,
}: {
  N?: Uint8Array;
  G?: Uint8Array;
} = {}): {
  clientPrivateEphemeral: Uint8Array;
  clientPublicEphemeral: Uint8Array;
} {
  const modulo = byteArrayToBigInt(moduloBytes);
  const generator = byteArrayToBigInt(generatorBytes);
  while (true) {
    const clientPrivateEphemeral = generateRandomExponent(modulo);
    const clientPublicEphemeral = modPow(
      generator,
      clientPrivateEphemeral,
      modulo
    );
    if (clientPublicEphemeral > 1n) {
      return {
        clientPrivateEphemeral: hexStringToByteArray(
          clientPrivateEphemeral.toString(16)
        ),
        clientPublicEphemeral: hexStringToByteArray(
          clientPublicEphemeral.toString(16)
        ),
      };
    }
  }
}

function modNegative(a: bigint, n: bigint): bigint {
  while (a < 0n) {
    a += n;
  }
  return a % n;
}

type ClientSharedHashOptions =
  | { sharedHash: Uint8Array }
  | { clientPublicEphemeral: Uint8Array };
export async function deriveSessionKey({
  username,
  password,
  salt,
  clientPrivateEphemeral,
  clientPublicEphemeral,
  serverPublicEphemeral,
  deriveMultiplier = deriveMultiplierSRP6a,
  digest = digestPBKDF2,
  N: moduloBytes = N,
  G: generatorBytes = G,
  algorithm = "SHA-256",
  ...options
}: ClientSharedHashOptions & {
  username: string;
  password: string;
  salt: Uint8Array;
  clientPrivateEphemeral: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  deriveMultiplier?: DeriveMultiplierFn;
  digest?: DigestFn;
  N?: Uint8Array;
  G?: Uint8Array;
  algorithm?: "SHA-1" | "SHA-256";
}): Promise<Uint8Array> {
  const u = byteArrayToBigInt(
    "sharedHash" in options
      ? options.sharedHash
      : await deriveSharedHash({
          clientPublicEphemeral,
          serverPublicEphemeral,
          algorithm,
          N: moduloBytes,
        })
  );
  const k = byteArrayToBigInt(
    await deriveMultiplier(moduloBytes, generatorBytes)
  );
  const modulo = byteArrayToBigInt(moduloBytes);
  const { x: xBytes } = await deriveVerifier(
    { username, password },
    {
      salt,
      N: moduloBytes,
      G: generatorBytes,
      digest,
    }
  );
  const x = byteArrayToBigInt(xBytes);
  // B - k * g^x
  const generator = byteArrayToBigInt(generatorBytes);
  const B = byteArrayToBigInt(serverPublicEphemeral);
  const base = modNegative(
    B - ((k * modPow(generator, x, modulo)) % modulo),
    modulo
  );
  const exp = (byteArrayToBigInt(clientPrivateEphemeral) + u * x) % modulo;
  const S = bigIntToByteArray(modPow(base, exp, modulo));
  return new Uint8Array(await crypto.subtle.digest(algorithm, S));
}

export async function deriveClientProof({
  username,
  salt,
  clientPublicEphemeral,
  serverPublicEphemeral,
  sessionKey,
  N: moduloBytes = N,
  G: generatorBytes = G,
  algorithm = "SHA-256",
}: {
  username: string;
  salt: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  sessionKey: Uint8Array;
  N?: Uint8Array;
  G?: Uint8Array;
  algorithm?: "SHA-1" | "SHA-256";
}) {
  const moduloHash = new Uint8Array(
    await crypto.subtle.digest(algorithm, moduloBytes)
  );
  const gHash = new Uint8Array(
    await crypto.subtle.digest(algorithm, generatorBytes)
  );
  const xored = new Uint8Array(
    Array.from({ length: moduloHash.length }).map(
      (_, i) => moduloHash[i] ^ gHash[i]
    )
  );
  const usernameHash = new Uint8Array(
    await crypto.subtle.digest(algorithm, new TextEncoder().encode(username))
  );
  return new Uint8Array(
    await crypto.subtle.digest(
      algorithm,
      concatByteArrays(
        xored,
        usernameHash,
        salt,
        clientPublicEphemeral,
        serverPublicEphemeral,
        sessionKey
      )
    )
  );
}

export * from "./verifier";
export * from "./multiplier";
