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

### Advanced usage

For more advanced usage, you can refer to sources of [ClientSession](src/client.ts) and [ServerSession](src/server.ts) classes. You can also refer to the [test](test) directory for more examples.

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
