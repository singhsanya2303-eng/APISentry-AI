import test from "node:test";
import assert from "node:assert/strict";

import { normalizeTheme, THEME_STORAGE_KEY } from "../src/theme/themeContext.js";

test("theme storage key is the centralized apisentry key", () => {
  assert.equal(THEME_STORAGE_KEY, "apisentry.theme");
});

test("valid saved theme values normalize to themselves", () => {
  assert.equal(normalizeTheme("light"), "light");
  assert.equal(normalizeTheme("dark"), "dark");
});

test("invalid or missing saved theme values normalize to null", () => {
  for (const value of [null, undefined, "", "system", "LIGHT", "dark-mode", 42]) {
    assert.equal(normalizeTheme(value), null);
  }
});
