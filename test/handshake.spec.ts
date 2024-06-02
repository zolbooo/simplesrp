import { expect, test } from "vitest";

import {
  deriveVerifier,
  generateClientEphemeral,
  deriveSessionKey as deriveSessionKey_client,
} from "../src/srp/client";
import {
  generateServerEphemeral,
  deriveSessionKey as deriveSessionKey_server,
} from "../src/srp/server";
import { SRP_PARAMETERS_RFC5054_4096 } from "../src/constants";

import { byteArrayToHexString } from "../src/utils";

test("it should produce correct shared secret", async () => {
  // 1. Client init
  const username = "alice";
  const password = "test@password";
  const { salt, verifier } = await deriveVerifier({ username, password });
  const { clientPublicEphemeral, clientPrivateEphemeral } =
    generateClientEphemeral();
  // 2. Server init
  const { serverPublicEphemeral, serverPrivateEphemeral } =
    await generateServerEphemeral({ verifier });
  // 3. Client-side shared session key
  const clientSharedKey = await deriveSessionKey_client({
    salt,
    username,
    password,
    clientPublicEphemeral,
    serverPublicEphemeral,
    clientPrivateEphemeral,
  });
  // 4. Server-side shared session key
  const serverSharedKey = await deriveSessionKey_server({
    verifier,
    clientPublicEphemeral,
    serverPublicEphemeral,
    serverPrivateEphemeral,
  });
  // Handshake done
  expect(byteArrayToHexString(clientSharedKey)).toBe(
    byteArrayToHexString(serverSharedKey)
  );
});

test("it should produce correct shared secret with RFC5054 4096-bit parameters", async () => {
  // 1. Client init
  const username = "alice";
  const password = "test@password";
  const { salt, verifier } = await deriveVerifier(
    { username, password },
    { parameters: SRP_PARAMETERS_RFC5054_4096 }
  );
  const { clientPublicEphemeral, clientPrivateEphemeral } =
    generateClientEphemeral(SRP_PARAMETERS_RFC5054_4096);
  // 2. Server init
  const { serverPublicEphemeral, serverPrivateEphemeral } =
    await generateServerEphemeral({
      verifier,
      parameters: SRP_PARAMETERS_RFC5054_4096,
    });
  // 3. Client-side shared session key
  const clientSharedKey = await deriveSessionKey_client({
    salt,
    username,
    password,
    serverPublicEphemeral,
    clientPublicEphemeral,
    clientPrivateEphemeral,
    parameters: SRP_PARAMETERS_RFC5054_4096,
  });
  // 4. Server-side shared session key
  const serverSharedKey = await deriveSessionKey_server({
    verifier,
    clientPublicEphemeral,
    serverPublicEphemeral,
    serverPrivateEphemeral,
    parameters: SRP_PARAMETERS_RFC5054_4096,
  });
  // Handshake done
  expect(byteArrayToHexString(clientSharedKey)).toBe(
    byteArrayToHexString(serverSharedKey)
  );
});
