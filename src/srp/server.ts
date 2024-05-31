import { modPow } from "../math";
import { G, K, N } from "../constants";
import {
  byteArrayToHexString,
  generateRandomExponent,
  hexStringToByteArray,
  padData,
} from "../utils";

export function deriveMultiplierSRP6(_: Uint8Array, __: Uint8Array) {
  return hexStringToByteArray(K.toString(16));
}
export async function deriveMultiplierSRP6a(N: Uint8Array, g: Uint8Array) {
  const hashInput = new Uint8Array(N.length * 2);
  hashInput.set(N);
  hashInput.set(padData(g, N), N.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", hashInput));
}
export async function deriveMultiplierSRP6a_SHA1(N: Uint8Array, g: Uint8Array) {
  const paddedG = new Uint8Array(N.length);
  paddedG.set(g, N.length - g.length);
  paddedG.set(
    Array.from({ length: N.length - g.length }).map(() => 0),
    0
  );
  const hashInput = new Uint8Array(N.length * 2);
  hashInput.set(N);
  hashInput.set(paddedG, N.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-1", hashInput));
}

export async function generateServerEphemeral({
  verifier,
  deriveMultiplier = deriveMultiplierSRP6,
  generator = G,
  modulo = N,
  unsafe_staticPrivateEphemeral,
}: {
  verifier: Uint8Array;
  deriveMultiplier?: (
    N: Uint8Array,
    g: Uint8Array
  ) => Uint8Array | Promise<Uint8Array>;
  generator?: bigint;
  modulo?: bigint;
  unsafe_staticPrivateEphemeral?: bigint;
}) {
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
    return { serverPrivateEphemeral, serverPublicEphemeral };
  }
}
