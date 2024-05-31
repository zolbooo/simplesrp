import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp/verifier";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import { N_1024, testDigestRFC5054, s, v } from "./test-vector-rfc5054";

test("it should derive verifier according as per RFC5054", async () => {
  const { verifier } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
    salt: hexStringToByteArray(s),
    // See: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
    digest: testDigestRFC5054,
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
    salt: salt,
  });
  expect(verifier1).toEqual(verifier2);
});
