import { N } from "../constants";
import { bigIntToByteArray, padData } from "../utils";

export async function deriveSharedHash({
  clientPublicEphemeral,
  serverPublicEphemeral,
  N: modulo = N,
  algorithm = "SHA-256",
}: {
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  N?: bigint;
  algorithm?: "SHA-256" | "SHA-1";
}): Promise<Uint8Array> {
  const moduloBytes = bigIntToByteArray(modulo);
  const paddedLeft = padData(clientPublicEphemeral, moduloBytes);
  const paddedRight = padData(serverPublicEphemeral, moduloBytes);
  const hashInput = new Uint8Array(paddedLeft.length + paddedRight.length);
  hashInput.set(paddedLeft);
  hashInput.set(paddedRight, paddedLeft.length);
  return new Uint8Array(await crypto.subtle.digest(algorithm, hashInput));
}
