import { K } from "../constants";
import { hexStringToByteArray, padData } from "../utils";

export type DeriveMultiplierFn = (
  N: Uint8Array,
  g: Uint8Array
) => Uint8Array | Promise<Uint8Array>;

export const deriveMultiplierSRP6: DeriveMultiplierFn = (
  _: Uint8Array,
  __: Uint8Array
) => {
  return hexStringToByteArray(K.toString(16));
};
export const deriveMultiplierSRP6a: DeriveMultiplierFn = async (
  N: Uint8Array,
  g: Uint8Array
) => {
  const hashInput = new Uint8Array(N.length * 2);
  hashInput.set(N);
  hashInput.set(padData(g, N), N.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", hashInput));
};
export const deriveMultiplierSRP6a_SHA1: DeriveMultiplierFn = async (
  N: Uint8Array,
  g: Uint8Array
) => {
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
};
