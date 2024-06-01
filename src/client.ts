import * as constants from "./constants";

import { concatByteArrays, safeByteArrayEquals } from "./utils";

import { DeriveMultiplierFn } from "./srp/multiplier";
import { DigestFn, deriveVerifier } from "./srp/verifier";
import {
  deriveSessionKey,
  deriveClientProof,
  generateClientEphemeral,
} from "./srp/client";

export class ClientSession {
  static deriveVerifier = deriveVerifier;

  private algorithm: "SHA-1" | "SHA-256";
  private G = constants.G;
  private N = constants.N;

  private digest?: DigestFn;
  private deriveMultiplier?: DeriveMultiplierFn;
  constructor({
    G,
    N,
    algorithm = "SHA-256",
    digest,
    deriveMultiplier,
  }: {
    G?: Uint8Array;
    N?: Uint8Array;
    algorithm?: "SHA-256" | "SHA-1";
    digest?: DigestFn;
    deriveMultiplier?: DeriveMultiplierFn;
  } = {}) {
    this.algorithm = algorithm;
    if (G) {
      this.G = G;
    }
    if (N) {
      this.N = N;
    }
    if (digest) {
      this.digest = digest;
    }
    if (deriveMultiplier) {
      this.deriveMultiplier = deriveMultiplier;
    }
  }

  private clientPrivateEphemeral?: Uint8Array;
  private clientPublicEphemeral?: Uint8Array;

  initializeHandshake(): { clientPublicEphemeral: Uint8Array } {
    const { clientPrivateEphemeral, clientPublicEphemeral } =
      generateClientEphemeral({ N: this.N, G: this.G });
    this.clientPublicEphemeral = clientPublicEphemeral;
    this.clientPrivateEphemeral = clientPrivateEphemeral;
    return { clientPublicEphemeral };
  }

  private clientProof?: Uint8Array;
  private sessionKey?: Uint8Array;

  async finalizeHandshake({
    username,
    password,
    salt,
    serverPublicEphemeral,
  }: {
    username: string;
    password: string;
    salt: Uint8Array;
    serverPublicEphemeral: Uint8Array;
  }): Promise<{ clientProof: Uint8Array }> {
    if (!this.clientPublicEphemeral || !this.clientPrivateEphemeral) {
      throw Error(
        "Session was not initialized. Did you call initializeHandshake method?"
      );
    }

    const sessionKey = await deriveSessionKey({
      username,
      password,
      salt,
      clientPublicEphemeral: this.clientPublicEphemeral,
      clientPrivateEphemeral: this.clientPrivateEphemeral,
      serverPublicEphemeral: serverPublicEphemeral,
      N: this.N,
      G: this.G,
      algorithm: this.algorithm,
      digest: this.digest,
      deriveMultiplier: this.deriveMultiplier,
    });
    this.sessionKey = sessionKey;
    const clientProof = await deriveClientProof({
      username,
      salt,
      serverPublicEphemeral,
      clientPublicEphemeral: this.clientPublicEphemeral,
      sessionKey,
      N: this.N,
      G: this.G,
      algorithm: this.algorithm,
    });
    this.clientProof = clientProof;
    return { clientProof };
  }

  async verifyServerProof(
    serverProof: Uint8Array
  ): Promise<{ serverVerified: boolean }> {
    if (!this.clientProof || !this.clientPublicEphemeral || !this.sessionKey) {
      throw Error(
        "Expected client proof to be calculated first. Did you call finalizeHandshake method?"
      );
    }
    const expectedServerProof = new Uint8Array(
      await crypto.subtle.digest(
        this.algorithm,
        concatByteArrays(
          this.clientPublicEphemeral,
          this.clientProof,
          this.sessionKey
        )
      )
    );
    return {
      serverVerified: safeByteArrayEquals(expectedServerProof, serverProof),
    };
  }
}
