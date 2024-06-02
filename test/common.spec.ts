import { expect, test } from "vitest";
import { deriveSharedHash } from "../src/srp/common";
import { byteArrayToHexString } from "../src/utils";

import { A, B, parameters, u } from "./test-vector-rfc5054";

test("it should derive correct value u", async () => {
  const sharedHash = await deriveSharedHash({
    clientPublicEphemeral: A,
    serverPublicEphemeral: B,
    algorithm: "SHA-1",
    parameters,
  });
  expect(byteArrayToHexString(sharedHash).toString()).toEqual(
    byteArrayToHexString(u).toLowerCase()
  );
});
