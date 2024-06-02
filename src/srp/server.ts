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
  unsafe_skipOutputHashing = false,
  ...options
}: ({ sharedHash: Uint8Array } | { serverPublicEphemeral: Uint8Array }) & {
  verifier: Uint8Array;
  clientPublicEphemeral: Uint8Array;
  serverPrivateEphemeral: Uint8Array;
  parameters?: SRPParameterSet;
  unsafe_skipOutputHashing?: boolean;
}) {
  const v = byteArrayToBigInt(verifier);
  const u = byteArrayToBigInt(
    "sharedHash" in options
      ? options.sharedHash
      : await deriveSharedHash({
          clientPublicEphemeral,
          serverPublicEphemeral: options.serverPublicEphemeral,
          parameters,
        })
  );
  const A = byteArrayToBigInt(clientPublicEphemeral);
  const b = byteArrayToBigInt(serverPrivateEphemeral);
  const N = byteArrayToBigInt(parameters.N);
  const S = modPow((A * modPow(v, u, N)) % N, b, N);
  if (unsafe_skipOutputHashing) {
    return bigIntToByteArray(S);
  }
  return new Uint8Array(
    await crypto.subtle.digest(parameters.algorithm, bigIntToByteArray(S))
  );
}

export async function deriveServerProof({
  clientPublicEphemeral,
  clientProof,
  sessionKey,
  parameters = defaultParameters,
}: {
  clientPublicEphemeral: Uint8Array;
  clientProof: Uint8Array;
  sessionKey: Uint8Array;
  parameters?: SRPParameterSet;
}): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      parameters.algorithm,
      concatByteArrays(clientPublicEphemeral, clientProof, sessionKey)
    )
  );
}

export * from "./multiplier";
