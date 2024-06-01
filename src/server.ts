import * as constants from "./constants";
import { safeByteArrayEquals } from "./utils";

import {
  deriveSessionKey,
  deriveServerProof,
  generateServerEphemeral,
} from "./srp/server";
import { DeriveMultiplierFn } from "./srp/multiplier";

export class ServerSession {
  private algorithm: "SHA-1" | "SHA-256";
  private G = constants.G;
  private N = constants.N;

  private deriveMultiplier?: DeriveMultiplierFn;
  constructor({
    G,
    N,
    algorithm = "SHA-256",
    deriveMultiplier,
  }: {
    G?: Uint8Array;
    N?: Uint8Array;
    algorithm?: "SHA-256" | "SHA-1";
    deriveMultiplier?: DeriveMultiplierFn;
  } = {}) {
    this.algorithm = algorithm;
    if (G) {
      this.G = G;
    }
    if (N) {
      this.N = N;
    }
    if (deriveMultiplier) {
      this.deriveMultiplier = deriveMultiplier;
    }
  }

  private clientVerifier?: Uint8Array;
  private clientPublicEphemeral?: Uint8Array;
  private serverPrivateEphemeral?: Uint8Array;
  private serverPublicEphemeral?: Uint8Array;

  async prepareHandshake({
    verifier,
    clientPublicEphemeral,
  }: {
    verifier: Uint8Array;
    clientPublicEphemeral: Uint8Array;
  }): Promise<{ serverPublicEphemeral: Uint8Array }> {
    const { serverPrivateEphemeral, serverPublicEphemeral } =
      await generateServerEphemeral({
        verifier,
        G: this.G,
        N: this.N,
        deriveMultiplier: this.deriveMultiplier,
      });
    this.clientVerifier = verifier;
    this.clientPublicEphemeral = clientPublicEphemeral;
    this.serverPrivateEphemeral = serverPrivateEphemeral;
    this.serverPublicEphemeral = serverPublicEphemeral;
    return { serverPublicEphemeral };
  }

  async finalizeHandshake({
    username,
    salt,
    clientProof,
  }: {
    username: string;
    salt: Uint8Array;
    clientProof: Uint8Array;
  }): Promise<{
    serverProof: Uint8Array;
    clientVerified: boolean;
  }> {
    if (
      !this.clientVerifier ||
      !this.clientPublicEphemeral ||
      !this.serverPublicEphemeral ||
      !this.serverPrivateEphemeral
    ) {
      throw Error(
        "Session is not initialized. Did you call prepareHandshake method?"
      );
    }

    const sessionKey = await deriveSessionKey({
      verifier: this.clientVerifier,
      clientPublicEphemeral: this.clientPublicEphemeral,
      serverPublicEphemeral: this.serverPublicEphemeral,
      serverPrivateEphemeral: this.serverPrivateEphemeral,
      N: this.N,
      algorithm: this.algorithm,
    });
    const { expectedClientProof, serverProof } = await deriveServerProof({
      username,
      salt,
      sessionKey,
      clientPublicEphemeral: this.clientPublicEphemeral,
      serverPublicEphemeral: this.serverPublicEphemeral,
      N: this.N,
      G: this.G,
      algorithm: this.algorithm,
    });
    return {
      serverProof,
      clientVerified: safeByteArrayEquals(clientProof, expectedClientProof),
    };
  }
}
