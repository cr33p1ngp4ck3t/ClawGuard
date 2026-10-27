import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { ApiError, fetchEvents, fetchStats, fetchPolicy } from "./api.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("admin requests authenticate without caching secrets or audit data", async () => {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(JSON.stringify({ events: [], count: 0 }), { status: 200 });
  };
  await fetchEvents("admin-key", 100, "high", "research-agent");
  await fetchStats("admin-key");
  await fetchPolicy("admin-key");
  assert.equal(calls.length, 3);
  for (const { url, options } of calls) {
    assert.equal(options.headers.Authorization, "Bearer admin-key");
    assert.equal(options.cache, "no-store");
    assert.ok(!url.includes("admin-key"));
  }
  assert.ok(calls[0].url.includes("limit=100&risk_level=high&agent_id=research-agent"));
});

test("authentication errors preserve status and a human reason", async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Invalid admin key" }), { status: 401 });
  await assert.rejects(fetchStats("bad-key"), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 401);
    assert.match(error.message, /Invalid admin key/);
    return true;
  });
});

test("non-JSON gateway errors retain the HTTP status", async () => {
  globalThis.fetch = async () => new Response("Unavailable", { status: 503 });
  await assert.rejects(fetchStats("admin-key"), /503/);
});

test("invalid successful JSON reports a readable error", async () => {
  globalThis.fetch = async () => new Response("not json", { status: 200 });
  await assert.rejects(fetchStats("admin-key"), /invalid response/);
});
