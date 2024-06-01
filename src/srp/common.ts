import { N } from "../constants";
import { padData } from "../utils";

export async function deriveSharedHash({
  clientPublicEphemeral,
  serverPublicEphemeral,
  N: moduloBytes = N,
  algorithm = "SHA-256",
}: {
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  N?: Uint8Array;
  algorithm?: "SHA-256" | "SHA-1";
}): Promise<Uint8Array> {
  const paddedLeft = padData(clientPublicEphemeral, moduloBytes);
  const paddedRight = padData(serverPublicEphemeral, moduloBytes);
  const hashInput = new Uint8Array(paddedLeft.length + paddedRight.length);
  hashInput.set(paddedLeft);
  hashInput.set(paddedRight, paddedLeft.length);
  return new Uint8Array(await crypto.subtle.digest(algorithm, hashInput));
}
