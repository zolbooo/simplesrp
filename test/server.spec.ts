import { expect, test } from "vitest";

import {
  deriveSessionKey,
  generateServerEphemeral,
  deriveMultiplierSRP6a_SHA1,
} from "../src/srp/server";
import { G } from "../src/constants";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import { A, B, N_1024, b, k, premaster, u, v } from "./test-vector-rfc5054";

test("it should derive multiplier as per RFC5054", async () => {
  const multiplier = await deriveMultiplierSRP6a_SHA1(
    hexStringToByteArray(N_1024),
    hexStringToByteArray(G.toString(16))
  );
  expect(multiplier).toEqual(hexStringToByteArray(k));
});

test("it should generate server ephemeral value as per RFC5054", async () => {
  const { serverPrivateEphemeral, serverPublicEphemeral } =
    await generateServerEphemeral({
      N: BigInt("0x" + N_1024),
      verifier: hexStringToByteArray(v),
      deriveMultiplier: deriveMultiplierSRP6a_SHA1,
      unsafe_staticPrivateEphemeral: BigInt("0x" + b),
    });
  expect(serverPrivateEphemeral).toEqual(hexStringToByteArray(b));
  expect(serverPublicEphemeral).toEqual(hexStringToByteArray(B));
});

test("it should derive session key as per RFC5054", async () => {
  const sessionKey = await deriveSessionKey({
    verifier: hexStringToByteArray(v),
    sharedHash: hexStringToByteArray(u),
    clientPublicEphemeral: hexStringToByteArray(A),
    serverPrivateEphemeral: hexStringToByteArray(b),
    N: BigInt("0x" + N_1024),
  });
  expect(byteArrayToHexString(sessionKey).toLowerCase()).toBe(
    premaster.toLowerCase()
  );
});
