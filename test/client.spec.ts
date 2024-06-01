import { expect, test } from "vitest";

import { byteArrayToBigInt, byteArrayToHexString } from "../src/utils";
import {
  deriveSessionKey,
  generateClientEphemeral,
  deriveMultiplierSRP6a_SHA1,
} from "../src/srp/client";

import {
  a,
  A,
  B,
  s,
  u,
  N_1024,
  premaster,
  testDigestRFC5054,
} from "./test-vector-rfc5054";

test("it should generate a proper client ephemeral value", () => {
  const { clientPrivateEphemeral, clientPublicEphemeral } =
    generateClientEphemeral();
  expect(byteArrayToBigInt(clientPrivateEphemeral)).toBeGreaterThan(1n);
  expect(byteArrayToBigInt(clientPublicEphemeral)).toBeGreaterThan(1n);
});

// Please let me know if following test fails, since it's a rare event :)
test("it should (almost) never generate the same client ephemeral value", () => {
  const { clientPublicEphemeral: clientPublicEphemeral1 } =
    generateClientEphemeral();
  const { clientPublicEphemeral: clientPublicEphemeral2 } =
    generateClientEphemeral();
  expect(clientPublicEphemeral1).not.toEqual(clientPublicEphemeral2);
});

test("it should derive premaster secret correctly as per RFC5054", async () => {
  const premasterSecret = await deriveSessionKey({
    clientPrivateEphemeral: a,
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    sharedHash: u,
    salt: s,
    password: "password123",
    N: N_1024,
    deriveMultiplier: deriveMultiplierSRP6a_SHA1,
    digest: testDigestRFC5054,
  });
  expect(byteArrayToHexString(premasterSecret).toLowerCase()).toBe(
    premaster.toLowerCase()
  );
});
