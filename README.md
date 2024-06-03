# simplesrp

## Table of contents

- [Introduction](#introduction)
- [Usage](#usage)
  - [Simple usage](#simple-usage)
  - [Advanced usage](#advanced-usage)
- [How SRP works](#how-srp-works)

## Introduction

SimpleSRP is a simple implementation of the Secure Remote Password protocol (SRP-6a) in pure Javascript. It is designed to be easy to use and understand, and is suitable for use in both Node.js, browser and the edge.

It uses following features of Javascript:

- BigInt
- WebCrypto API
- TextEncoder

## Usage

There are two main classes in this library: `ClientSession` and `ServerSession`. You can import them like this:

```javascript
import { ClientSession } from "simplesrp";
```

If you want more advanced usage, you can import individual functions for specific entrypoints and override configuration options. For example, to import the server functions, you can do this:

```javascript
import {
  generateServerEphemeral,
  deriveSessionKey,
  deriveServerProof,
  deriveMultiplierSRP6a,
} from "simplesrp/server";
```

### Simple usage

For example of simple flow, you can refer to [test/scenario.test.ts](test/scenario.spec.ts).

#### Registration

There are two possible ways to register a new user:

1. Client-side registration: prompt for a username and password, derive the verifier and send it to the server.

```javascript
import { ClientSession } from "simplesrp";

const username = "TODO";
const password = "TODO";
const { salt, verifier } = await ClientSession.deriveVerifier({
  username,
  password,
});
// Submit the username, salt and verifier to the server, you can discard the password at this point.
```

2. Server-side registration: retrieve the username and password from the client, derive the verifier and store it in the database on the server side.

```javascript
import { deriveVerifier } from "simplesrp/verifier";

const { username, password } = clientRequest;
const { salt, verifier } = await deriveVerifier({ username, password });
// Store the username, salt and verifier in the database.
```

**Please note that the verifier is a secret value and should be stored securely.**

**Also, if you are using the server-side registration with custom password hashing, you must use the same hashing algorithm and parameters on the client.**

#### Authentication

1. Generate client-side handshake data and send it to the server.

```javascript
import { ClientSession } from "simplesrp";

const username = "TODO";
const clientSession = new ClientSession();
const { clientPublicEphemeral } = clientSession.initializeHandshake();
// Send the clientPublicEphemeral along with the username to the server.
api.requestAuthChallenge({ username, clientPublicEphemeral });
```

2. Retrieve the verifier and salt from the database, generate server-side handshake data and send it to the client.

```javascript
import { ServerSession } from "simplesrp";

const { username, clientPublicEphemeral } = clientRequest;
const { salt, verifier } = await retrieveVerifier(username); // TODO: Implement `retrieveVerifier` function
const serverSession = new ServerSession();
const { serverPublicEphemeral } = serverSession.prepareHandshake({
  username,
  salt,
  verifier,
  clientPublicEphemeral,
});
// TODO: Send the salt and serverPublicEphemeral to the client.
const responseData = { salt, serverPublicEphemeral };
```

3. (Optional) Export the server session state. **WARNING: the state contains sensitive values, handle it carefully!**

```javascript
const authenticationSessionState = serverSession.exportState();
// TODO: Save the state in database/cache/cookies, whichever is appropriate.
// IMPORTANT: Make sure to encrypt the state if you decide to not save it on the server.
res.cookie("auth-challenge", await encrypt(authenticationSessionState));
```

4. Generate client proof and send it to the server.

```javascript
const { salt, serverPublicEphemeral } = serverResponse;
const { clientProof } = clientSession.finalizeHandshake({
  username,
  salt,
  serverPublicEphemeral,
  verifier,
});
// TODO: Send the clientProof to the server.
await api.sendAuthChallengeResponse({ username, clientProof });
```

6. (Optional) Import the saved server session state.

```javascript
const authenticationSessionState = await decrypt(req.cookies["auth-challenge"]);
const serverSession = ServerSession.fromState(authenticationSessionState);
```

7. Verify the client proof and generate the server proof.

```javascript
const { clientProof } = clientRequest;
const { clientVerified, serverProof } = serverSession.verifyClientProof({
  clientProof,
});
if (!clientVerified) {
  throw Error("Forbidden"); // TODO: Handle case when user's username or password is invalid
}
// TODO: The user is authenticated, create a session for them and optionally send the serverProof to the client.
res.cookie("auth-session", sessionToken);
const serverResponse = { serverProof }; // Optional, send serverProof if you want client to verify the server's identity.
```

8. (Optional) Verify the server's identity by checking the server proof.

```javascript
const { serverProof } = serverResponse;
const { serverVerified } = await clientSession.verifyServerProof(serverProof);
if (!serverVerified) {
  throw Error("Invalid server"); // TODO: Handle case when server's identity is invalid
}
```

### Advanced usage

For more advanced usage, you can refer to sources of [ClientSession](src/client.ts) and [ServerSession](src/server.ts) classes. You can also refer to the [test](test) directory for more examples.

It's possible to override most of behavior by creating own `SRPParameterSet`. You can specify:

- `N`: modulo of the group
- `g`: generator of the group
- `algorithm` hash algorithm used in calculations, available values are `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`. Please don't use `SHA-1` as the algorithm is obsolete, it's available for testing.
- `deriveMultiplier`: function used to derive multiplier, default is `deriveMultiplierSRP6a`.

You can always override the default configuration options by passing them as arguments to the class constructor or to the underlying functions.

```javascript
import { SRP_PARAMETERS_RFC5054_3072 } from "simplesrp";
const clientSession = new ClientSession({
  parameters: SRP_PARAMETERS_RFC5054_3072, // Use 3072-bit parameters with SHA-384 instead of the default 2048-bit parameters with SHA-256.
});
```

You can change the password hashing function by passing a custom `digest` to the `deriveVerifier` function.

```javascript
import { deriveVerifier } from "simplesrp/verifier";
import { SRP_PARAMETERS_RFC5054_3072 } from "simplesrp";

const { salt, verifier } = await deriveVerifier(
  { username, password },
  {
    parameters: SRP_PARAMETERS_RFC5054_3072,
    saltLength: 32, // You can change the salt length, the default is 16 bytes.
    digest: scrypt, // You can use a custom password hashing function, the default is pbkdf2-sha256 with 600000 iterations.
  }
);
```

## How SRP works

The Secure Remote Password protocol is a password-authenticated key exchange protocol. It allows a client to authenticate to a server, without sending the password over the network. Instead, the client and server exchange a series of messages, which are used to derive a shared secret. This shared secret can then be used to encrypt further communication between the client and server or to prove the client's and server's identity.

During registration, the client generates a random salt and hashes the password with the salt. Then client computes a value called verifier from the hashed password. The verifier is then sent to the server.

Authentication flow:

1. Client generates a random ephemeral value $a$ and computes a public ephemeral value $A$ from it. The public ephemeral value $A$ is sent to the server.
2. Server retrieves a verifier $v$ and salt $s$ corresponding to the client's identity. Server generates a random ephemeral value $b$ and computes a public ephemeral value $B$ from it. The public ephemeral value $B$ is sent to the client.
3. Client and server compute a shared secret $S$ from the public ephemeral values and the verifier. The shared secret is used to derive a session key $K$.
4. Client generates a proof of the shared secret $M_1$ and sends it to the server.
5. Server verifies the proof and in case of success, generates its own proof $M_2$ and sends it to the client.
6. Client verifies the server's proof. (This step is optional)

If you want to know more about SRP, you can read the [original paper](http://srp.stanford.edu/). Also, you can check the [Wikipedia page](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).

The implementation of SRP in this library is based on the [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054) and [RFC 2945](https://datatracker.ietf.org/doc/html/rfc2945) with help of test vectors from [secure-remote-password/test-vectors](https://github.com/secure-remote-password/test-vectors).
