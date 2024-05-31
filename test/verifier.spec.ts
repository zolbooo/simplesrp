import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp/verifier";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import { I, N_1024, s, v } from "./test-vector-rfc5054";

test("it should derive verifier according as per RFC5054", async () => {
  const { verifier } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
    unsafe_staticSalt: hexStringToByteArray(s),
    // See: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
    digest: async ({ input, salt }) => {
      const innerInput = [I, ":", new TextDecoder().decode(input)].join("");
      const innerHash = await crypto.subtle.digest(
        "SHA-1",
        new TextEncoder().encode(innerInput)
      );
      expect(byteArrayToHexString(new Uint8Array(innerHash))).toBe(
        "d0a293c8c443c4b151f6c0f6982861d2334ee933"
      );
      const outerInput = hexStringToByteArray(
        byteArrayToHexString(salt) +
          byteArrayToHexString(new Uint8Array(innerHash))
      );
      const outerHash = await crypto.subtle.digest("SHA-1", outerInput);
      expect(byteArrayToHexString(new Uint8Array(outerHash))).toBe(
        "94b7555aabe9127cc58ccf4993db6cf84d16c124"
      );
      return new Uint8Array(outerHash);
    },
  });
  expect(byteArrayToHexString(verifier).toUpperCase()).toBe(v);
});

test("it should derive same verifier for same password and salt", async () => {
  const { verifier: verifier1, salt } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
  });
  const { verifier: verifier2 } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
    unsafe_staticSalt: salt,
  });
  expect(verifier1).toEqual(verifier2);
});
