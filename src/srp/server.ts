import { G, N } from "../constants";
import { modPow } from "../math";
import {
  concatByteArrays,
  bigIntToByteArray,
  byteArrayToBigInt,
  byteArrayToHexString,
  generateRandomExponent,
} from "../utils";
import { deriveClientProof } from "./client";

import { deriveSharedHash } from "./common";
import { deriveMultiplierSRP6a } from "./multiplier";

export async function generateServerEphemeral({
  verifier,
  deriveMultiplier = deriveMultiplierSRP6a,
  G: generatorBytes = G,
  N: moduloBytes = N,
  unsafe_staticPrivateEphemeral,
}: {
  verifier: Uint8Array;
  deriveMultiplier?: (
    N: Uint8Array,
    g: Uint8Array
  ) => Uint8Array | Promise<Uint8Array>;
  G?: Uint8Array;
  N?: Uint8Array;
  unsafe_staticPrivateEphemeral?: Uint8Array;
}): Promise<{
  serverPrivateEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
}> {
  const multiplier = BigInt(
    "0x" +
      byteArrayToHexString(await deriveMultiplier(moduloBytes, generatorBytes))
  );
  const modulo = byteArrayToBigInt(moduloBytes);
  const generator = byteArrayToBigInt(generatorBytes);
  while (true) {
    const serverPrivateEphemeral = unsafe_staticPrivateEphemeral
      ? byteArrayToBigInt(unsafe_staticPrivateEphemeral)
      : generateRandomExponent(modulo);
    const serverPublicEphemeral =
      (((multiplier * BigInt("0x" + byteArrayToHexString(verifier))) % modulo) +
        modPow(generator, serverPrivateEphemeral, modulo)) %
      modulo;
    if (serverPublicEphemeral === 0n) {
      if (unsafe_staticPrivateEphemeral) {
        throw new Error(
          "Incorrect private ephemeral value provided: public ephemeral value is 0."
        );
      }
      continue;
    }
    return {
      serverPrivateEphemeral: bigIntToByteArray(serverPrivateEphemeral),
      serverPublicEphemeral: bigIntToByteArray(serverPublicEphemeral),
    };
  }
}

export async function deriveSessionKey({
  verifier,
  clientPublicEphemeral,
  serverPrivateEphemeral,
  N: moduloBytes = N,
  algorithm = "SHA-256",
  ...options
}: ({ sharedHash: Uint8Array } | { serverPublicEphemeral: Uint8Array }) & {
  verifier: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPrivateEphemeral: Uint8Array;
  N?: Uint8Array;
  algorithm?: "SHA-1" | "SHA-256";
}) {
  const v = byteArrayToBigInt(verifier);
  const u = byteArrayToBigInt(
    "sharedHash" in options
      ? options.sharedHash
      : await deriveSharedHash({
          algorithm,
          clientPublicEphemeral,
          serverPublicEphemeral: options.serverPublicEphemeral,
          N: moduloBytes,
        })
  );
  const A = byteArrayToBigInt(clientPublicEphemeral);
  const b = byteArrayToBigInt(serverPrivateEphemeral);
  const modulo = byteArrayToBigInt(moduloBytes);
  const S = bigIntToByteArray(
    modPow((A * modPow(v, u, modulo)) % modulo, b, modulo)
  );
  return new Uint8Array(await crypto.subtle.digest(algorithm, S));
}

export async function deriveServerProof({
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
}): Promise<{ expectedClientProof: Uint8Array; serverProof: Uint8Array }> {
  const M1 = await deriveClientProof({
    username,
    salt,
    clientPublicEphemeral,
    serverPublicEphemeral,
    sessionKey,
    N: moduloBytes,
    G: generatorBytes,
    algorithm,
  });
  return {
    expectedClientProof: M1,
    serverProof: new Uint8Array(
      await crypto.subtle.digest(
        algorithm,
        concatByteArrays(clientPublicEphemeral, M1, sessionKey)
      )
    ),
  };
}

export * from "./multiplier";
