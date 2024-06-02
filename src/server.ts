import * as constants from "./constants";
import { safeByteArrayEquals } from "./utils";
import type { SRPParameterSet } from "./constants";

import {
  deriveSessionKey,
  deriveServerProof,
  generateServerEphemeral,
} from "./srp/server";
import { DeriveMultiplierFn } from "./srp/multiplier";

export class ServerSession {
  private algorithm: "SHA-1" | "SHA-256" = "SHA-256";
  private parameters: SRPParameterSet = constants.SRP_PARAMETERS_RFC5054_2048;

  private deriveMultiplier?: DeriveMultiplierFn;
  constructor({
    algorithm,
    parameters,
    deriveMultiplier,
  }: {
    algorithm?: "SHA-256" | "SHA-1";
    parameters?: SRPParameterSet;
    deriveMultiplier?: DeriveMultiplierFn;
  } = {}) {
    if (algorithm) {
      this.algorithm = algorithm;
    }
    if (parameters) {
      this.parameters = parameters;
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
        parameters: this.parameters,
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
    serverProof: Uint8Array | null;
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
      parameters: this.parameters,
      algorithm: this.algorithm,
    });
    const { expectedClientProof, serverProof } = await deriveServerProof({
      username,
      salt,
      sessionKey,
      clientPublicEphemeral: this.clientPublicEphemeral,
      serverPublicEphemeral: this.serverPublicEphemeral,
      parameters: this.parameters,
      algorithm: this.algorithm,
    });
    const clientVerified = safeByteArrayEquals(
      clientProof,
      expectedClientProof
    );
    return {
      // Don't return server proof if password is invalid!
      // This might compromise the security of user's password.
      // See: https://datatracker.ietf.org/doc/html/rfc2945#section-3
      serverProof: clientVerified ? serverProof : null,
      clientVerified,
    };
  }
}
