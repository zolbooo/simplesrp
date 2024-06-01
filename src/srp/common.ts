import { N } from "../constants";
import { concatByteArrays, padData } from "../utils";

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
  return new Uint8Array(
    await crypto.subtle.digest(
      algorithm,
      concatByteArrays(
        padData(clientPublicEphemeral, moduloBytes),
        padData(serverPublicEphemeral, moduloBytes)
      )
    )
  );
}
