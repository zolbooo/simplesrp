import { expect, test } from "vitest";

import { byteArrayToBigInt, byteArrayToHexString } from "../src/utils";
import {
  deriveSessionKey,
  deriveClientProof,
  generateClientEphemeral,
  deriveMultiplierSRP6aFactory,
} from "../src/srp/client";

import {
  a,
  A,
  B,
  s,
  u,
  I,
  p,
  K,
  expectedM1,
  parameters,
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

test("it should derive session key correctly", async () => {
  const sessionKey = await deriveSessionKey({
    clientPrivateEphemeral: a,
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    sharedHash: u,
    salt: s,
    username: I,
    password: p,
    parameters,
    algorithm: "SHA-1",
    deriveMultiplier: deriveMultiplierSRP6aFactory("SHA-1"),
    digest: testDigestRFC5054,
  });
  expect(byteArrayToHexString(sessionKey).toLowerCase()).toBe(
    byteArrayToHexString(K)
  );
});

test("should should derive client proof correctly", async () => {
  const sessionKey = await deriveSessionKey({
    clientPrivateEphemeral: a,
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    sharedHash: u,
    salt: s,
    username: I,
    password: p,
    parameters,
    algorithm: "SHA-1",
    deriveMultiplier: deriveMultiplierSRP6aFactory("SHA-1"),
    digest: testDigestRFC5054,
  });
  expect(byteArrayToHexString(sessionKey)).toBe(byteArrayToHexString(K));
  const clientProof = await deriveClientProof({
    username: I,
    salt: s,
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    sessionKey,
    parameters,
    algorithm: "SHA-1",
  });
  expect(byteArrayToHexString(clientProof)).toBe(
    byteArrayToHexString(expectedM1)
  );
});
