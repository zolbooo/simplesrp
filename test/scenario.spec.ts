import { expect, test } from "vitest";

import {
  ClientSession,
  ServerSession,
  SRP_PARAMETERS_RFC5054_3072,
} from "../src";

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
    username,
    salt,
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
    { clientProof }
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
    username,
    salt,
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
    { clientProof }
  );
  expect(clientVerified).toBe(false);
  expect(serverProof).toBe(null);
});

test("it should perform client-server handshake with RFC5054 3072 bit parameters properly", async () => {
  const username = "hello";
  const password = "world";
  const clientSession = new ClientSession({
    parameters: SRP_PARAMETERS_RFC5054_3072,
  });
  const serverSession = new ServerSession({
    parameters: SRP_PARAMETERS_RFC5054_3072,
  });
  // 1. Calculate verifier, submit it along with salt to the server
  const { salt, verifier } = await ClientSession.deriveVerifier(
    {
      username,
      password,
    },
    { parameters: SRP_PARAMETERS_RFC5054_3072 }
  );
  // 2. Initialize client session
  const { clientPublicEphemeral } = clientSession.initializeHandshake();
  // 3. Retrieve verifier for the user, initialize server session
  const { serverPublicEphemeral } = await serverSession.prepareHandshake({
    username,
    salt,
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
    { clientProof }
  );
  expect(clientVerified).toBe(true);
  // (Optional) 6. Client verifies server's proof
  if (!serverProof) {
    throw Error("serverProof is null, expected a non-null value");
  }
  const { serverVerified } = await clientSession.verifyServerProof(serverProof);
  expect(serverVerified).toBe(true);
});
