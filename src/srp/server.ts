import { modPow } from "../math";
import { G, N } from "../constants";
import {
  bigIntToByteArray,
  byteArrayToHexString,
  hexStringToByteArray,
  generateRandomExponent,
} from "../utils";

import { deriveMultiplierSRP6a } from "./multiplier";

export async function generateServerEphemeral({
  verifier,
  deriveMultiplier = deriveMultiplierSRP6a,
  G: generator = G,
  N: modulo = N,
  unsafe_staticPrivateEphemeral,
}: {
  verifier: Uint8Array;
  deriveMultiplier?: (
    N: Uint8Array,
    g: Uint8Array
  ) => Uint8Array | Promise<Uint8Array>;
  G?: bigint;
  N?: bigint;
  unsafe_staticPrivateEphemeral?: bigint;
}): Promise<{
  serverPrivateEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
}> {
  const multiplier = BigInt(
    "0x" +
      byteArrayToHexString(
        await deriveMultiplier(
          hexStringToByteArray(modulo.toString(16)),
          hexStringToByteArray(generator.toString(16))
        )
      )
  );
  while (true) {
    const serverPrivateEphemeral =
      unsafe_staticPrivateEphemeral ?? generateRandomExponent(modulo);
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

export * from "./multiplier";
