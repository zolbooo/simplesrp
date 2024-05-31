import { expect, test } from "vitest";

import {
  generateServerEphemeral,
  deriveMultiplierSRP6a_SHA1,
} from "../src/srp/server";
import { G } from "../src/constants";
import { hexStringToByteArray } from "../src/utils";

import { B, N_1024, b, k, v } from "./test-vector-rfc5054";

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
      modulo: BigInt("0x" + N_1024),
      verifier: hexStringToByteArray(v),
      deriveMultiplier: deriveMultiplierSRP6a_SHA1,
      unsafe_staticPrivateEphemeral: BigInt("0x" + b),
    });
  expect(serverPrivateEphemeral).toBe(BigInt("0x" + b));
  expect(serverPublicEphemeral).toBe(BigInt("0x" + B));
});
