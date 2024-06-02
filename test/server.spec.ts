import { expect, test } from "vitest";

import {
  deriveSessionKey,
  deriveServerProof,
  generateServerEphemeral,
  deriveMultiplierSRP6aFactory,
} from "../src/srp/server";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import {
  A,
  B,
  K,
  b,
  k,
  u,
  v,
  expectedM1,
  expectedM2,
  parameters,
} from "./test-vector-rfc5054";

test("it should derive multiplier as per RFC5054", async () => {
  const multiplier = await deriveMultiplierSRP6aFactory("SHA-1")(parameters);
  expect(multiplier).toEqual(hexStringToByteArray(k));
});

test("it should generate server ephemeral value as per RFC5054", async () => {
  const { serverPrivateEphemeral, serverPublicEphemeral } =
    await generateServerEphemeral({
      verifier: v,
      parameters,
      deriveMultiplier: deriveMultiplierSRP6aFactory("SHA-1"),
      unsafe_staticPrivateEphemeral: b,
    });
  expect(serverPrivateEphemeral).toEqual(b);
  expect(serverPublicEphemeral).toEqual(B);
});

test("it should derive session key as per RFC5054", async () => {
  const sessionKey = await deriveSessionKey({
    verifier: v,
    sharedHash: u,
    clientPublicEphemeral: A,
    serverPrivateEphemeral: b,
    parameters,
    algorithm: "SHA-1",
  });
  expect(byteArrayToHexString(sessionKey)).toBe(byteArrayToHexString(K));
});

test("it should server proof correctly", async () => {
  const clientProof = expectedM1;
  const serverProof = await deriveServerProof({
    clientProof,
    clientPublicEphemeral: A,
    sessionKey: K,
    algorithm: "SHA-1",
  });
  expect(byteArrayToHexString(serverProof)).toBe(expectedM2);
});
