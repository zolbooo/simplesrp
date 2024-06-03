import * as constants from "./constants";
import { safeByteArrayEquals } from "./utils";
import type { SRPParameterSet } from "./constants";

import {
  deriveSessionKey,
  deriveServerProof,
  generateServerEphemeral,
} from "./srp/server";
import { deriveClientProof } from "./srp/client";

export interface ServerState {
  username: string;
  salt: Uint8Array;
  clientVerifier: Uint8Array;
  serverPrivateEphemeral: Uint8Array;
  serverPublicEphemeral: Uint8Array;
}

export class ServerSession {
  private parameters: SRPParameterSet = constants.SRP_PARAMETERS_RFC5054_2048;

  private state?: ServerState;
  exportState(): ServerState {
    if (!this.state) {
      throw TypeError(
        "Session is not initialized. Did you call prepareHandshake or importState?"
      );
    }
    return this.state;
  }
  importState(state: ServerState): ServerSession {
    this.state = state;
    return this;
  }

  constructor({
    parameters,
  }: {
    parameters?: SRPParameterSet;
  } = {}) {
    if (parameters) {
      this.parameters = parameters;
    }
  }
  static fromState(
    state: ServerState,
    parameters?: SRPParameterSet
  ): ServerSession {
    return new ServerSession({ parameters }).importState(state);
  }

  async prepareHandshake({
    username,
    salt,
    verifier,
  }: {
    username: string;
    salt: Uint8Array;
    verifier: Uint8Array;
  }): Promise<{ serverPublicEphemeral: Uint8Array }> {
    const { serverPrivateEphemeral, serverPublicEphemeral } =
      await generateServerEphemeral({
        verifier,
        parameters: this.parameters,
      });
    this.state = {
      username,
      salt,
      clientVerifier: verifier,
      serverPrivateEphemeral,
      serverPublicEphemeral,
    };
    return { serverPublicEphemeral };
  }

  async finalizeHandshake({
    clientPublicEphemeral,
    clientProof,
  }: {
    clientPublicEphemeral: Uint8Array;
    clientProof: Uint8Array;
  }): Promise<{
    serverProof: Uint8Array | null;
    clientVerified: boolean;
  }> {
    if (!this.state) {
      throw Error(
        "Session is not initialized. Did you call prepareHandshake or importState?"
      );
    }

    const sessionKey = await deriveSessionKey({
      clientPublicEphemeral,
      verifier: this.state.clientVerifier,
      serverPublicEphemeral: this.state.serverPublicEphemeral,
      serverPrivateEphemeral: this.state.serverPrivateEphemeral,
      parameters: this.parameters,
    });
    const expectedClientProof = await deriveClientProof({
      sessionKey,
      clientPublicEphemeral,
      username: this.state.username,
      salt: this.state.salt,
      serverPublicEphemeral: this.state.serverPublicEphemeral,
      parameters: this.parameters,
    });
    const clientVerified = safeByteArrayEquals(
      clientProof,
      expectedClientProof
    );
    // Don't return server proof if password is invalid!
    // This might compromise the security of user's password.
    // See: https://datatracker.ietf.org/doc/html/rfc2945#section-3
    if (!clientVerified) {
      return { serverProof: null, clientVerified };
    }
    return {
      serverProof: await deriveServerProof({
        clientPublicEphemeral,
        clientProof,
        sessionKey,
        parameters: this.parameters,
      }),
      clientVerified,
    };
  }
}
