import { expect, test } from "vitest";

import { generateClientEphemeral } from "../src/srp/client";

test("it should generate a proper client ephemeral value", () => {
  const { clientPrivateEphemeral, clientPublicEphemeral } =
    generateClientEphemeral();
  expect(clientPrivateEphemeral).toBeGreaterThan(1n);
  expect(clientPublicEphemeral).toBeGreaterThan(1n);
});

// Please let me know if following test fails, since it's a rare event :)
test("it should (almost) never generate the same client ephemeral value", () => {
  const { clientPublicEphemeral: clientPublicEphemeral1 } =
    generateClientEphemeral();
  const { clientPublicEphemeral: clientPublicEphemeral2 } =
    generateClientEphemeral();
  expect(clientPublicEphemeral1).not.toEqual(clientPublicEphemeral2);
});