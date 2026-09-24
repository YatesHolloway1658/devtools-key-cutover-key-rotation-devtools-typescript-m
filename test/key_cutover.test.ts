import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { decideCutover, InfraiClient, runCutover, verifyBuildEvent } from "../src/key_cutover.ts";

test("holds the old key while a deployment still reports the old value", () => {
  const decision = decideCutover([
    { deployment: "clinical-portal", stillUsesOldValue: false },
    { deployment: "consent-worker", stillUsesOldValue: true },
  ]);
  assert.equal(decision, "hold-old-key");
});

test("accepts a signed build event", () => {
  const body = '{"release":"2026.09.15"}';
  const signature = createSignature(body, "event-secret");
  assert.equal(verifyBuildEvent(body, signature, "event-secret"), true);
});

for (const failSearch of [false, true]) {
  test(`revokes the created key ${failSearch ? "after a failed search" : "after success"}`, async () => {
    const calls: string[] = [];
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      calls.push(path);
      const failure = failSearch && path === "/v1/logs/search";
      return new Response(JSON.stringify(failure
        ? { ok: false, error: { code: "SEARCH_FAILED" } }
        : { ok: true, data: path.endsWith("/create") ? { key_id: "test-key-id", key: "secret" } : {} }), {
        status: failure ? 400 : 200,
      });
    };
    const client = new InfraiClient("test-token", fetcher as typeof fetch);
    if (failSearch) await assert.rejects(runCutover(client), /SEARCH_FAILED/);
    else await runCutover(client);
    assert.deepEqual(calls, [
      "/v1/account/keys/create",
      "/v1/account/keys/rotate/test-key-id",
      "/v1/logs/search",
      "/v1/account/keys/revoke/test-key-id",
    ]);
  });
}

function createSignature(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}
