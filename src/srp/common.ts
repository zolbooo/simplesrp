import { concatByteArrays, padData } from "../utils";
import { SRPParameterSet, defaultParameters } from "../constants";

export async function deriveSharedHash({
  clientPublicEphemeral,
  serverPublicEphemeral,
  parameters = defaultParameters,
}: {
  clientPublicEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
  parameters?: SRPParameterSet;
}): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      parameters.algorithm,
      concatByteArrays(
        padData(clientPublicEphemeral, parameters.N),
        padData(serverPublicEphemeral, parameters.N)
      )
    )
  );
}
