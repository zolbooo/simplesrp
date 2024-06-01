import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp/verifier";
import { byteArrayToHexString } from "../src/utils";

import { G } from "../src/constants";
import { N_1024, testDigestRFC5054, s, v } from "./test-vector-rfc5054";

test("it should derive verifier according as per RFC5054", async () => {
  const { verifier } = await deriveVerifier("password123", {
    G,
    N: N_1024,
    salt: s,
    // See: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
    digest: testDigestRFC5054,
  });
  expect(byteArrayToHexString(verifier).toLowerCase()).toBe(
    byteArrayToHexString(v).toLowerCase()
  );
});

test("it should derive same verifier for same password and salt", async () => {
  const { verifier: verifier1, salt } = await deriveVerifier("password123", {
    G,
    N: N_1024,
  });
  const { verifier: verifier2 } = await deriveVerifier("password123", {
    G,
    salt,
    N: N_1024,
  });
  expect(verifier1).toEqual(verifier2);
});
