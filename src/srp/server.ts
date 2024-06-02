import { modPow } from "../math";
import { SRPParameterSet, defaultParameters } from "../constants";
import {
  concatByteArrays,
  bigIntToByteArray,
  byteArrayToBigInt,
  byteArrayToHexString,
  generateRandomExponent,
} from "../utils";

import { deriveSharedHash } from "./common";
import { deriveClientProof } from "./client";
import { DeriveMultiplierFn, deriveMultiplierSRP6a } from "./multiplier";

export async function generateServerEphemeral({
  verifier,
  deriveMultiplier = deriveMultiplierSRP6a,
  parameters = defaultParameters,
  unsafe_staticPrivateEphemeral,
}: {
  verifier: Uint8Array;
  deriveMultiplier?: DeriveMultiplierFn;
  parameters?: SRPParameterSet;
  unsafe_staticPrivateEphemeral?: Uint8Array;
}): Promise<{
  serverPrivateEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
}> {
  const multiplier = BigInt(
    "0x" + byteArrayToHexString(await deriveMultiplier(parameters))
  );
  const modulo = byteArrayToBigInt(parameters.N);
  const generator = byteArrayToBigInt(parameters.G);
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
  parameters = defaultParameters,
  algorithm = "SHA-256",
  ...options
}: ({ sharedHash: Uint8Array } | { serverPublicEphemeral: Uint8Array }) & {
  verifier: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPrivateEphemeral: Uint8Array;
  parameters?: SRPParameterSet;
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
          parameters,
        })
  );
  const A = byteArrayToBigInt(clientPublicEphemeral);
  const b = byteArrayToBigInt(serverPrivateEphemeral);
  const N = byteArrayToBigInt(parameters.N);
  const S = bigIntToByteArray(modPow((A * modPow(v, u, N)) % N, b, N));
  return new Uint8Array(await crypto.subtle.digest(algorithm, S));
}

export async function deriveServerProof({
  clientPublicEphemeral,
  clientProof,
  sessionKey,
  algorithm = "SHA-256",
}: {
  clientPublicEphemeral: Uint8Array;
  clientProof: Uint8Array;
  sessionKey: Uint8Array;
  algorithm?: "SHA-1" | "SHA-256";
}): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      algorithm,
      concatByteArrays(clientPublicEphemeral, clientProof, sessionKey)
    )
  );
}

export * from "./multiplier";
