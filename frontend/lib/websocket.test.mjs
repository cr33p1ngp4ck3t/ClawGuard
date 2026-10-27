import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const source = ts.transpileModule(readFileSync(new URL("../hooks/useWebSocket.ts", import.meta.url), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS },
}).outputText;

function session(apiKey = "admin-key") {
  const sockets = [];
  const retries = new Map();
  const events = [];
  const errors = [];
  const states = [];
  let cleanup;
  class Socket {
    sent = [];
    constructor(url) { this.url = url; sockets.push(this); }
    send(message) { this.sent.push(message); }
    close() { this.onclose?.({ code: 1000 }); }
  }
  const exports = {};
  vm.runInNewContext(source, {
    exports, process, WebSocket: Socket,
    setTimeout: (callback) => { const id = retries.size + 1; retries.set(id, callback); return id; },
    clearTimeout: (id) => retries.delete(id),
    require: (name) => name === "react" ? {
      useState: (initial) => [initial, (value) => states.push(value)],
      useEffectEvent: (callback) => callback,
      useEffect: (callback) => { cleanup = callback(); },
    } : require(name),
  });
  exports.useWebSocket(apiKey, (event) => events.push(event), (message, unauthorized) => errors.push({ message, unauthorized }));
  return { sockets, retries, events, errors, states, cleanup };
}

test("signed-out dashboard opens no socket", () => {
  assert.equal(session("").sockets.length, 0);
});

test("socket authenticates in its first message and only becomes live on acknowledgement", () => {
  const client = session();
  const socket = client.sockets[0];
  assert.ok(!socket.url.includes("admin-key"));
  socket.onopen();
  assert.deepEqual(JSON.parse(socket.sent[0]), { token: "admin-key" });
  assert.deepEqual(client.states, []);
  socket.onmessage({ data: JSON.stringify({ type: "authenticated" }) });
  assert.deepEqual(client.states, ["admin-key"]);
  const event = { id: "event-1" };
  socket.onmessage({ data: JSON.stringify({ type: "new_event", payload: event }) });
  assert.deepEqual(client.events.map((received) => received.id), [event.id]);
});

test("authentication rejection reports an error without retrying", () => {
  const client = session();
  client.sockets[0].onclose({ code: 1008 });
  assert.equal(client.errors[0].unauthorized, true);
  assert.match(client.errors[0].message, /key rejected/);
  assert.equal(client.retries.size, 0);
});

test("sign-out cancels queued reconnects and ignores late messages", () => {
  const client = session();
  const socket = client.sockets[0];
  socket.onclose({ code: 1006 });
  assert.equal(client.retries.size, 1);
  client.cleanup();
  assert.equal(client.retries.size, 0);
  socket.onmessage({ data: JSON.stringify({ type: "new_event", payload: { id: "late" } }) });
  assert.deepEqual(client.events, []);
  assert.equal(client.sockets.length, 1);
});
