import { G, N } from "../constants";
import { modPow } from "../math";
import { generateRandomExponent, hexStringToByteArray } from "../utils";

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

export * from "./verifier";
