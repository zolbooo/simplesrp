import { G, N } from "../constants";
import { modPow } from "../math";
import {
  bigIntToByteArray,
  byteArrayToBigInt,
  hexStringToByteArray,
  generateRandomExponent,
} from "../utils";

import { deriveSharedHash } from "./common";
import { DigestFn, deriveVerifier, digestPBKDF2 } from "./verifier";
import { DeriveMultiplierFn, deriveMultiplierSRP6a } from "./multiplier";

export function generateClientEphemeral({
  N: modulo = N,
  G: generator = G,
}: {
  N?: bigint;
  G?: bigint;
} = {}): {
  clientPrivateEphemeral: Uint8Array;
  clientPublicEphemeral: Uint8Array;
} {
  while (true) {
    const clientPrivateEphemeral = generateRandomExponent(N);
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
export async function deriveSessionKey({
  password,
  salt,
  clientPrivateEphemeral,
  clientPublicEphemeral,
  serverPublicEphemeral,
  sharedHash,
  deriveMultiplier = deriveMultiplierSRP6a,
  digest = digestPBKDF2,
  N: modulo = N,
  G: generator = G,
}: {
  password: string;
  salt: Uint8Array;
  clientPrivateEphemeral: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  sharedHash?: Uint8Array;
  deriveMultiplier?: DeriveMultiplierFn;
  digest?: DigestFn;
  N?: bigint;
  G?: bigint;
}): Promise<Uint8Array> {
  const u = byteArrayToBigInt(
    sharedHash ??
      (await deriveSharedHash({
        clientPublicEphemeral,
        serverPublicEphemeral,
        N: modulo,
      }))
  );
  const k = byteArrayToBigInt(
    await deriveMultiplier(
      bigIntToByteArray(modulo),
      bigIntToByteArray(generator)
    )
  );
  const { x: xBytes } = await deriveVerifier(password, {
    salt,
    N: modulo,
    G: generator,
    digest,
  });
  const x = byteArrayToBigInt(xBytes);
  // B - k * g^x
  const base = modNegative(
    byteArrayToBigInt(serverPublicEphemeral) -
      ((k * modPow(generator, x, modulo)) % modulo),
    modulo
  );
  const exp = (byteArrayToBigInt(clientPrivateEphemeral) + u * x) % modulo;
  return bigIntToByteArray(modPow(base, exp, modulo));
}

export * from "./verifier";
export * from "./multiplier";
