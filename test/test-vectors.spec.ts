import { expect, test } from "vitest";

import { testVectors } from "./test-vectors.json";
import { testDigestRFC5054 } from "./test-vector-rfc5054";

import {
  byteArrayToBigInt,
  byteArrayToHexString,
  hexStringToByteArray,
} from "../src/utils";

import { deriveVerifier } from "../src/srp/verifier";
import { deriveSharedHash } from "../src/srp/common";
import {
  deriveClientProof,
  deriveSessionKey as deriveSessionKey_client,
} from "../src/srp/client";
import {
  deriveServerProof,
  deriveSessionKey as deriveSessionKey_server,
} from "../src/srp/server";
import type { SRPParameterSet } from "../src";

test("outputs must match with test vectors", async () => {
  const algorithmMapping: Partial<
    Record<string, SRPParameterSet["algorithm"]>
  > = {
    sha1: "SHA-1",
    sha256: "SHA-256",
    sha384: "SHA-384",
    sha512: "SHA-512",
  };
  for (const testVector of testVectors) {
    const algorithm = algorithmMapping[testVector.H];
    if (!algorithm) {
      continue;
    }
    const parameters: SRPParameterSet = {
      N: hexStringToByteArray(testVector.N),
      G: hexStringToByteArray(testVector.g),
      algorithm,
    };
    const {
      x: xBytes,
      salt,
      verifier,
    } = await deriveVerifier(
      {
        username: testVector.I,
        password: testVector.P,
      },
      {
        salt: hexStringToByteArray(testVector.s),
        digest: testDigestRFC5054,
        parameters,
      }
    );
    const x = byteArrayToBigInt(xBytes);
    expect(x.toString(16)).toBe(testVector.x);
    expect(byteArrayToHexString(verifier)).toBe(testVector.v);

    const clientPublicEphemeral = hexStringToByteArray(testVector.A);
    const clientPrivateEphemeral = hexStringToByteArray(testVector.a);
    const serverPublicEphemeral = hexStringToByteArray(testVector.B);
    const serverPrivateEphemeral = hexStringToByteArray(testVector.b);
    const sharedHash = await deriveSharedHash({
      clientPublicEphemeral,
      serverPublicEphemeral,
      parameters,
    });
    expect(byteArrayToHexString(sharedHash)).toBe(testVector.u);

    const S_client = await deriveSessionKey_client({
      username: testVector.I,
      password: testVector.P,
      salt,
      serverPublicEphemeral,
      clientPrivateEphemeral,
      sharedHash,
      parameters,
      unsafe_skipOutputHashing: true,
      digest: testDigestRFC5054,
    });
    expect(byteArrayToHexString(S_client)).toBe(testVector.S);
    const S_server = await deriveSessionKey_server({
      verifier,
      sharedHash,
      clientPublicEphemeral,
      serverPrivateEphemeral,
      parameters,
      unsafe_skipOutputHashing: true,
    });
    expect(byteArrayToHexString(S_server)).toBe(testVector.S);

    const serverSessionKey = new Uint8Array(
      await crypto.subtle.digest(parameters.algorithm, S_server)
    );
    expect(byteArrayToHexString(serverSessionKey)).toBe(testVector.K);
    const clientSessionKey = new Uint8Array(
      await crypto.subtle.digest(parameters.algorithm, S_client)
    );
    expect(byteArrayToHexString(clientSessionKey)).toBe(testVector.K);

    const clientProof = await deriveClientProof({
      username: testVector.I,
      salt,
      clientPublicEphemeral,
      serverPublicEphemeral,
      sessionKey: clientSessionKey,
      parameters,
    });
    expect(byteArrayToHexString(clientProof)).toBe(testVector.M1);

    const serverProof = await deriveServerProof({
      clientProof,
      clientPublicEphemeral,
      sessionKey: serverSessionKey,
      parameters,
    });
    expect(byteArrayToHexString(serverProof)).toBe(testVector.M2);
  }
});
