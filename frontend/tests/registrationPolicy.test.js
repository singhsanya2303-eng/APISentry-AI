import test from "node:test";
import assert from "node:assert/strict";

import { isPublicRegistrationAvailable } from "../src/services/registrationPolicy.js";

test("registration is available only outside production builds", () => {
  assert.equal(isPublicRegistrationAvailable({ PROD: false }), true);
  assert.equal(isPublicRegistrationAvailable({ PROD: true }), false);
  assert.equal(isPublicRegistrationAvailable({}), true);
  assert.equal(isPublicRegistrationAvailable(undefined), true);
});
