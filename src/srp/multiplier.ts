import { SRPParameterSet } from "../constants";
import { concatByteArrays, padData } from "../utils";

export type DeriveMultiplierFn = (
  parameters: SRPParameterSet
) => Uint8Array | Promise<Uint8Array>;

export const deriveMultiplierSRP6: DeriveMultiplierFn = (parameters) => {
  return concatByteArrays(parameters.G, parameters.N);
};

export const deriveMultiplierSRP6aFactory: (
  algorithm: "SHA-1" | "SHA-256"
) => DeriveMultiplierFn = (algorithm) => async (parameters) =>
  new Uint8Array(
    await crypto.subtle.digest(
      algorithm,
      concatByteArrays(parameters.N, padData(parameters.G, parameters.N))
    )
  );
export const deriveMultiplierSRP6a: DeriveMultiplierFn =
  deriveMultiplierSRP6aFactory("SHA-256");
