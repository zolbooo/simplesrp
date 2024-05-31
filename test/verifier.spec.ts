import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp";
import { byteArrayToHexString, hexStringToByteArray } from "../src/utils";

// See: https://datatracker.ietf.org/doc/html/rfc5054#appendix-A
const N_1024 = `
  EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
  9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
  8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
  7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
  FD5138FE 8376435B 9FC61D2F C0EB06E3
`.replace(/\s/g, "");
const I = "alice";
const s = "BEB25379 D1A8581E B5A72767 3A2441EE".replace(/\s/g, "");
const v = `
  7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
  9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
  C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
  EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
  E955A5E2 9E7AB245 DB2BE315 E2099AFB
`.replace(/\s/g, "");

test("it should derive verifier according as per RFC5054", async () => {
  const { verifier } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
    unsafe_staticSalt: hexStringToByteArray(s),
    // See: https://datatracker.ietf.org/doc/html/rfc5054#section-2.4
    digest: async ({ input, salt }) => {
      const innerInput = [I, ":", new TextDecoder().decode(input)].join("");
      const innerHash = await crypto.subtle.digest(
        "SHA-1",
        new TextEncoder().encode(innerInput)
      );
      expect(byteArrayToHexString(new Uint8Array(innerHash))).toBe(
        "d0a293c8c443c4b151f6c0f6982861d2334ee933"
      );
      const outerInput = hexStringToByteArray(
        byteArrayToHexString(salt) +
          byteArrayToHexString(new Uint8Array(innerHash))
      );
      const outerHash = await crypto.subtle.digest("SHA-1", outerInput);
      expect(byteArrayToHexString(new Uint8Array(outerHash))).toBe(
        "94b7555aabe9127cc58ccf4993db6cf84d16c124"
      );
      return new Uint8Array(outerHash);
    },
  });
  expect(byteArrayToHexString(verifier).toUpperCase()).toBe(v);
});

test("it should derive same verifier for same password and salt", async () => {
  const { verifier: verifier1, salt } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
  });
  const { verifier: verifier2 } = await deriveVerifier("password123", {
    N: BigInt("0x" + N_1024),
    G: 2n,
    unsafe_staticSalt: salt,
  });
  expect(verifier1).toEqual(verifier2);
});
