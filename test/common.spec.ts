import { expect, test } from "vitest";
import { deriveSharedHash } from "../src/srp/common";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

import { A, B, N_1024, u } from "./test-vector-rfc5054";

test("it should derive correct value u", async () => {
  const sharedHash = await deriveSharedHash({
    clientPublicEphemeral: hexStringToByteArray(A),
    serverPublicEphemeral: hexStringToByteArray(B),
    algorithm: "SHA-1",
    N: BigInt("0x" + N_1024),
  });
  expect(byteArrayToHexString(sharedHash).toString()).toEqual(u.toLowerCase());
});
