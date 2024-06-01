import { expect, test } from "vitest";

import {
  deriveSessionKey,
  deriveServerProof,
  generateServerEphemeral,
  deriveMultiplierSRP6a_SHA1,
} from "../src/srp/server";
import { G } from "../src/constants";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import { A, B, I, K, N_1024, b, k, s, u, v } from "./test-vector-rfc5054";

test("it should derive multiplier as per RFC5054", async () => {
  const multiplier = await deriveMultiplierSRP6a_SHA1(N_1024, G);
  expect(multiplier).toEqual(hexStringToByteArray(k));
});

test("it should generate server ephemeral value as per RFC5054", async () => {
  const { serverPrivateEphemeral, serverPublicEphemeral } =
    await generateServerEphemeral({
      N: N_1024,
      verifier: v,
      deriveMultiplier: deriveMultiplierSRP6a_SHA1,
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
    N: N_1024,
    algorithm: "SHA-1",
  });
  expect(byteArrayToHexString(sessionKey)).toBe(byteArrayToHexString(K));
});

export const expectedM2 = "9cab3c575a11de37d3ac1421a9f009236a48eb55";
test("it should server proof correctly", async () => {
  const { serverProof } = await deriveServerProof({
    username: I,
    salt: s,
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    sessionKey: K,
    N: N_1024,
    algorithm: "SHA-1",
  });
  expect(byteArrayToHexString(serverProof)).toBe(expectedM2);
});
