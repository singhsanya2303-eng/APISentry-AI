import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import viteConfigFactory from "../vite.config.js";

const ENV_KEY = "APISENTRY_VITE_ENV_DIR";
const originalEnvDir = process.env[ENV_KEY];
const originalViteKeys = new Map(
  Object.entries(process.env).filter(([key]) => key.startsWith("VITE_")),
);

for (const key of originalViteKeys.keys()) delete process.env[key];

function withEnvFile(contents, fn) {
  const dir = mkdtempSync(join(tmpdir(), "apisentry-vite-config-"));
  process.env[ENV_KEY] = dir;
  if (contents !== null) writeFileSync(join(dir, ".env"), contents, "utf8");
  try {
    return fn();
  } finally {
    if (originalEnvDir === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = originalEnvDir;
    rmSync(dir, { recursive: true, force: true });
  }
}

test.after(() => {
  for (const [key, value] of originalViteKeys) process.env[key] = value;
});

test("production build config requires a non-loopback HTTPS API base", () => {
  withEnvFile("VITE_API_BASE_URL=https://api.example.test\n", () => {
    const config = viteConfigFactory({ mode: "production", command: "build" });
    assert.equal(
      config.define.__APISENTRY_API_BASE__,
      JSON.stringify("https://api.example.test"),
    );
  });
});

test("production build config rejects missing or loopback API base", () => {
  withEnvFile("", () => {
    assert.throws(
      () => viteConfigFactory({ mode: "production", command: "build" }),
      /VITE_API_BASE_URL is required/,
    );
  });
  withEnvFile("VITE_API_BASE_URL=http://127.0.0.1:8000\n", () => {
    assert.throws(
      () => viteConfigFactory({ mode: "production", command: "build" }),
      /non-loopback HTTPS origin/,
    );
  });
});

test("production build config rejects credential-bearing or non-origin API bases", () => {
  for (const value of [
    "https://user:password@api.example.test",
    "https://api.example.test/backend",
    "https://api.example.test/?token=example",
    "https://api.example.test/#fragment",
  ]) {
    withEnvFile(`VITE_API_BASE_URL=${value}\n`, () => {
      assert.throws(
        () => viteConfigFactory({ mode: "production", command: "build" }),
        /origin-only HTTPS URL/,
      );
    });
  }
});

test("build config keeps rejecting secret-like VITE names", () => {
  withEnvFile(
    "VITE_API_BASE_URL=https://api.example.test\nVITE_JWT_SECRET_KEY=test-value\n",
    () => {
      assert.throws(
        () => viteConfigFactory({ mode: "production", command: "build" }),
        /backend-secret-like VITE_/,
      );
    },
  );
});

test("development config does not require an HTTPS API base", () => {
  withEnvFile("", () => {
    const config = viteConfigFactory({ mode: "development", command: "serve" });
    assert.equal(config.define, undefined);
  });
});
