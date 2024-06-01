import { expect, test } from "vitest";

import { ClientSession, ServerSession } from "../src";

test("it should perform client-server handshake properly", async () => {
  const username = "hello";
  const password = "world";
  const clientSession = new ClientSession();
  const serverSession = new ServerSession();
  // 1. Calculate verifier, submit it along with salt to the server
  const { salt, verifier } = await ClientSession.deriveVerifier({
    username,
    password,
  });
  // 2. Initialize client session
  const { clientPublicEphemeral } = clientSession.initializeHandshake();
  // 3. Retrieve verifier for the user, initialize server session
  const { serverPublicEphemeral } = await serverSession.prepareHandshake({
    verifier,
    clientPublicEphemeral,
  });
  // 4. Finalize client handshake with server's value
  const { clientProof } = await clientSession.finalizeHandshake({
    username,
    password,
    salt,
    serverPublicEphemeral,
  });
  // 5. Server finalizes handshake, verifies this user
  const { serverProof, clientVerified } = await serverSession.finalizeHandshake(
    { username, salt, clientProof }
  );
  expect(clientVerified).toBe(true);
  // (Optional) 6. Client can verify server's proof
  if (!serverProof) {
    throw Error("serverProof is null, expected a non-null value");
  }
  const { serverVerified } = await clientSession.verifyServerProof(serverProof);
  expect(serverVerified).toBe(true);
});

test("it should reject handshake with the incorrect password", async () => {
  const username = "hello";
  const clientSession = new ClientSession();
  const serverSession = new ServerSession();
  // 1. Calculate verifier, submit it along with salt to the server
  const { salt, verifier } = await ClientSession.deriveVerifier({
    username,
    password: "world",
  });
  // 2. Initialize client session
  const { clientPublicEphemeral } = clientSession.initializeHandshake();
  // 3. Retrieve verifier for the user, initialize server session
  const { serverPublicEphemeral } = await serverSession.prepareHandshake({
    verifier,
    clientPublicEphemeral,
  });
  // 4. Finalize client handshake with server's value
  const { clientProof } = await clientSession.finalizeHandshake({
    username,
    password: "invalid-password",
    salt,
    serverPublicEphemeral,
  });
  // 5. Server finalizes handshake, verifies this user
  const { serverProof, clientVerified } = await serverSession.finalizeHandshake(
    { username, salt, clientProof }
  );
  expect(clientVerified).toBe(false);
  expect(serverProof).toBe(null);
});
