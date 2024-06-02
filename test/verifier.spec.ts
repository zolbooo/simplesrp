import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp/verifier";
import { byteArrayToHexString } from "../src/utils";

import {
  s,
  v,
  I,
  p,
  x,
  parameters,
  testDigestRFC5054,
} from "./test-vector-rfc5054";

test("it should derive verifier according as per RFC5054", async () => {
  const { x: derivedX, verifier } = await deriveVerifier(
    { username: I, password: p },
    {
      salt: s,
      parameters,
      // See: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
      digest: testDigestRFC5054,
    }
  );
  expect(byteArrayToHexString(derivedX).toLowerCase()).toBe(x.toLowerCase());
  expect(byteArrayToHexString(verifier).toLowerCase()).toBe(
    byteArrayToHexString(v).toLowerCase()
  );
});

test("it should derive same verifier for same password and salt", async () => {
  const { verifier: verifier1, salt } = await deriveVerifier(
    { username: I, password: p },
    { parameters }
  );
  const { verifier: verifier2 } = await deriveVerifier(
    { username: I, password: p },
    { salt, parameters }
  );
  expect(verifier1).toEqual(verifier2);
});
