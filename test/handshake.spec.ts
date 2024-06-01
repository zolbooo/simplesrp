import { expect, test } from "vitest";

import { deriveVerifier } from "../src/srp/verifier";
import {
  generateServerEphemeral,
  deriveSessionKey as deriveSessionKey_server,
} from "../src/srp/server";
import {
  generateClientEphemeral,
  deriveSessionKey as deriveSessionKey_client,
} from "../src/srp/client";
import { byteArrayToHexString } from "../src/utils";

test("it should produce correct shared secret", async () => {
  // 1. Client init
  const password = "test@password";
  const { salt, verifier } = await deriveVerifier(password);
  const { clientPublicEphemeral, clientPrivateEphemeral } =
    generateClientEphemeral();
  // 2. Server init
  const { serverPublicEphemeral, serverPrivateEphemeral } =
    await generateServerEphemeral({ verifier });
  // 3. Client-side shared session key
  const clientSharedKey = await deriveSessionKey_client({
    salt,
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
