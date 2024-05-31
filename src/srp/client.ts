import { G, N } from "../constants";
import { modPow } from "../math";
import { generateRandomExponent } from "../utils";

export function generateClientEphemeral({
  modulo = N,
  generator = G,
}: {
  modulo?: bigint;
  generator?: bigint;
} = {}): {
  clientPrivateEphemeral: bigint;
  clientPublicEphemeral: bigint;
} {
  while (true) {
    const clientPrivateEphemeral = generateRandomExponent(N);
    const clientPublicEphemeral = modPow(
      generator,
      clientPrivateEphemeral,
      modulo
    );
    if (clientPublicEphemeral > 1n) {
      return { clientPrivateEphemeral, clientPublicEphemeral };
    }
  }
}

export * from "./verifier";
