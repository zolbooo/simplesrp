import { SRPParameterSet } from "../constants";
import { concatByteArrays, padData } from "../utils";

export type DeriveMultiplierFn = (
  parameters: SRPParameterSet
) => Uint8Array | Promise<Uint8Array>;

export const deriveMultiplierSRP6a: DeriveMultiplierFn = async (parameters) =>
  new Uint8Array(
    await crypto.subtle.digest(
      parameters.algorithm,
      concatByteArrays(parameters.N, padData(parameters.G, parameters.N))
    )
  );
