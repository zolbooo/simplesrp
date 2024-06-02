import * as constants from "./constants";

import { SRPParameterSet } from "./constants";
import { concatByteArrays, safeByteArrayEquals } from "./utils";

import { DigestFn, deriveVerifier } from "./srp/verifier";
import {
  deriveSessionKey,
  deriveClientProof,
  generateClientEphemeral,
} from "./srp/client";

export class ClientSession {
  static deriveVerifier = deriveVerifier;

  private parameters: SRPParameterSet = constants.SRP_PARAMETERS_RFC5054_2048;

  private digest?: DigestFn;
  constructor({
    parameters,
    digest,
  }: {
    parameters?: SRPParameterSet;
    digest?: DigestFn;
  } = {}) {
    if (parameters) {
      this.parameters = parameters;
    }
    if (digest) {
      this.digest = digest;
    }
  }

  private clientPrivateEphemeral?: Uint8Array;
  private clientPublicEphemeral?: Uint8Array;

  initializeHandshake(): { clientPublicEphemeral: Uint8Array } {
    const { clientPrivateEphemeral, clientPublicEphemeral } =
      generateClientEphemeral(this.parameters);
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
      parameters: this.parameters,
      digest: this.digest,
    });
    this.sessionKey = sessionKey;
    const clientProof = await deriveClientProof({
      username,
      salt,
      serverPublicEphemeral,
      clientPublicEphemeral: this.clientPublicEphemeral,
      sessionKey,
      parameters: this.parameters,
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
        this.parameters.algorithm,
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
