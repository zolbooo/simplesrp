import { expect, test } from "vitest";

import { ClientSession, ServerSession } from "../src";

test("it should reject handshake if username has changed", async () => {
  const username = "alice";
  const password = "password";
  const { salt, verifier } = await ClientSession.deriveVerifier({
    username,
    password,
  });
  const clientSession = new ClientSession();
  const { clientPublicEphemeral } = clientSession.initializeHandshake();
  const serverSession = new ServerSession();
  const { serverPublicEphemeral } = await serverSession.prepareHandshake({
    username,
    salt,
    verifier,
    clientPublicEphemeral,
  });
  const { clientProof } = await clientSession.finalizeHandshake({
    username: "eve",
    password,
    salt,
    serverPublicEphemeral,
  });
  const { clientVerified, serverProof } = await serverSession.finalizeHandshake(
    { clientProof }
  );
  expect(clientVerified).toBe(false);
  expect(serverProof).toBe(null);
});

test("it should reject handshake if password was incorrect", async () => {
  const username = "alice";
  const password = "password";
  const { salt, verifier } = await ClientSession.deriveVerifier({
    username,
    password,
  });
  const clientSession = new ClientSession();
  const { clientPublicEphemeral } = clientSession.initializeHandshake();
  const serverSession = new ServerSession();
  const { serverPublicEphemeral } = await serverSession.prepareHandshake({
    username,
    salt,
    verifier,
    clientPublicEphemeral,
  });
  const { clientProof } = await clientSession.finalizeHandshake({
    username,
    password: "incorrect",
    salt,
    serverPublicEphemeral,
  });
  const { clientVerified, serverProof } = await serverSession.finalizeHandshake(
    { clientProof }
  );
  expect(clientVerified).toBe(false);
  expect(serverProof).toBe(null);
});
