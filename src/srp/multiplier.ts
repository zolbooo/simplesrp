import { G, N } from "../constants";
import { concatByteArrays, padData } from "../utils";

export type DeriveMultiplierFn = (
  N: Uint8Array,
  g: Uint8Array
) => Uint8Array | Promise<Uint8Array>;

export const deriveMultiplierSRP6: DeriveMultiplierFn = (
  _: Uint8Array,
  __: Uint8Array
) => {
  return concatByteArrays(G, N);
};
export const deriveMultiplierSRP6a: DeriveMultiplierFn = async (
  N: Uint8Array,
  g: Uint8Array
) => {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", concatByteArrays(N, padData(g, N)))
  );
};
export const deriveMultiplierSRP6a_SHA1: DeriveMultiplierFn = async (
  N: Uint8Array,
  g: Uint8Array
) => {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-1", concatByteArrays(N, padData(g, N)))
  );
};
