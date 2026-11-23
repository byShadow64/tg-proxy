// Test the shipped module with ordinary in-memory Workers platform adapters.
// No Cloudflare account, network connection or service deployment is involved.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../worker/telegram-worker.mjs", import.meta.url), "utf8");
const adapter = "data:text/javascript," + encodeURIComponent("export const connect = (...args) => globalThis.workerConnect(...args);");
assert.equal(source.split('from "cloudflare:sockets"').length, 2);
const worker = await import("data:text/javascript," + encodeURIComponent(source.replace('from "cloudflare:sockets"', `from ${JSON.stringify(adapter)}`)));
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
class Endpoint {
  events = new Map();
  sent = [];
  closes = [];
  accept() { assert.equal(this.binaryType, "arraybuffer"); this.accepted = true; }
  addEventListener(type, listener) { this.events.set(type, listener); }
  emit(type, data) { this.events.get(type)?.({ data }); }
  close(code, reason) { this.closes.push({ code, reason }); }
  send(data) { this.sent.push(new Uint8Array(data)); }
}
let lastServer;
globalThis.WebSocketPair = class {
  constructor() { this[0] = {}; this[1] = lastServer = new Endpoint(); }
};
globalThis.Response = class {
  constructor(body, options) { Object.assign(this, options); this.body = body; this.headers = new Headers(options.headers); }
};
function socketFixture({ hold = false, failWrite = false, opened = Promise.resolve() } = {}) {
  const gate = deferred();
  const closed = deferred();
  let control;
  const stats = { writes: [], activeWrites: 0, peakWrites: 0, close: 0, cancel: 0, abort: 0 };
  const socket = {
    opened,
    closed: closed.promise,
    readable: new ReadableStream({ start(controller) { control = controller; }, cancel() { stats.cancel++; } }),
    writable: new WritableStream({
      async write(data) {
        stats.activeWrites++;
        stats.peakWrites = Math.max(stats.peakWrites, stats.activeWrites);
        stats.writes.push(new Uint8Array(data));
        try {
          if (failWrite) throw new Error("ordinary synthetic transport failure");
          if (hold) await gate.promise;
        } finally { stats.activeWrites--; }
      },
      abort() { stats.abort++; },
    }),
    close() { stats.close++; gate.resolve(); closed.resolve(); },
  };
  return { socket, stats, gate, control: () => control, closed };
}
function binary(size, value = 0) { return new Uint8Array(size).fill(value).buffer; }
function request(query = "dst=149.154.167.220&dc=2", headers = {}) {
  return new Request("https://relay.example/apiws?" + query, {
    headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "binary", ...headers },
  });
}

test("Telegram catalogue accepts ordinary IPv4/IPv6 DCs and redirects", () => {
  for (const address of ["149.154.167.220", "91.108.4.1", "185.76.151.255", "91.105.193.1", "2001:b28:f23d::1", "2a0a:f280:ffff::1"]) {
    assert.equal(worker.isTelegramDestination(address), true, address);
  }
  for (const address of ["example.com", "127.0.0.1", "192.0.2.1", "149.154.176.1", "2001:db8::1", "091.108.4.1", "91.108.4.1:443", "2001:b28:f23d::1%1"]) {
    assert.equal(worker.isTelegramDestination(address), false, address);
  }
});

test("request policy rejects unsupported inputs before opening a socket", async () => {
  let connects = 0;
  globalThis.workerConnect = () => { connects++; throw new Error("must not connect"); };
  for (const input of [request("dst=example.com"), request("dst=127.0.0.1"), request("dst=149.154.167.220&dst=91.108.4.1"),
    request("dst=149.154.167.220&dc=0"), request("dst=149.154.167.220", { "Sec-WebSocket-Protocol": "text" }),
    new Request("https://relay.example/other"), new Request("https://relay.example/apiws?dst=149.154.167.220")]) {
    assert.notEqual((await worker.default.fetch(input)).status, 101);
  }
  assert.equal(connects, 0);
});

test("actual fetch negotiates binary and forwards an ordinary init to fixed TCP/443", async () => {
  const fixture = socketFixture();
  let target;
  globalThis.workerConnect = address => { target = address; return fixture.socket; };
  const response = await worker.default.fetch(request());
  assert.equal(response.status, 101);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), "binary");
  assert.deepEqual(target, { hostname: "149.154.167.220", port: 443 });
  assert.equal(lastServer.accepted, true);
  lastServer.emit("message", binary(64, 7));
  await tick();
  assert.deepEqual(fixture.stats.writes, [new Uint8Array(64).fill(7)]);
  lastServer.emit("close");
  await tick();
  assert.equal(fixture.stats.close, 1);
  assert.equal(fixture.stats.abort, 1);
  assert.equal(fixture.stats.cancel, 1);
});

test("serial queue preserves ordinary 64KiB writes while TCP writer is pending", async () => {
  const fixture = socketFixture({ hold: true });
  const server = new Endpoint();
  worker.bridge(server, fixture.socket);
  for (const value of [1, 2, 3]) server.emit("message", binary(65536, value));
  await tick();
  assert.equal(fixture.stats.writes.length, 1);
  fixture.gate.resolve();
  await tick();
  assert.deepEqual(fixture.stats.writes.map(value => value[0]), [1, 2, 3]);
  assert.equal(fixture.stats.peakWrites, 1);
  server.emit("close");
  await tick();
});

test("queue counts in-flight bytes, closes on its byte bound and discards pending writes", async () => {
  const fixture = socketFixture({ hold: true });
  const server = new Endpoint();
  worker.bridge(server, fixture.socket);
  server.emit("message", binary(worker.MAX_MESSAGE_BYTES));
  server.emit("message", binary(worker.MAX_MESSAGE_BYTES));
  server.emit("message", binary(1));
  await tick();
  assert.equal(server.closes.length, 1);
  assert.equal(server.closes[0].reason, "Upload queue limit");
  assert.equal(fixture.stats.close, 1);
  assert.ok(fixture.stats.writes.length <= 1);
});

test("small-message queue has an independent count bound", async () => {
  const fixture = socketFixture({ hold: true });
  const server = new Endpoint();
  worker.bridge(server, fixture.socket);
  for (let index = 0; index <= worker.MAX_PENDING_MESSAGES; index++) server.emit("message", binary(1));
  await tick();
  assert.equal(server.closes[0].reason, "Upload queue limit");
  assert.equal(fixture.stats.close, 1);
});

test("binary message bound, empty data and text fail closed", async () => {
  for (const data of [binary(worker.MAX_MESSAGE_BYTES + 1), binary(0), "text"]) {
    const fixture = socketFixture();
    const server = new Endpoint();
    worker.bridge(server, fixture.socket);
    server.emit("message", data);
    await tick();
    assert.equal(server.closes[0].reason, "Invalid binary message");
    assert.equal(fixture.stats.writes.length, 0);
    assert.equal(fixture.stats.close, 1);
  }
});

test("TCP replies preserve bytes in <=64KiB WS messages and EOF closes both ends", async () => {
  const fixture = socketFixture();
  const server = new Endpoint();
  worker.bridge(server, fixture.socket);
  const payload = new Uint8Array(131073).map((_, index) => index % 251);
  fixture.control().enqueue(payload);
  fixture.control().close();
  await tick();
  assert.deepEqual(server.sent.map(value => value.length), [65536, 65536, 1]);
  assert.deepEqual(Buffer.concat(server.sent), Buffer.from(payload));
  assert.equal(fixture.stats.close, 1);
});

test("ordinary write, read, socket and WebSocket failures each clean up once", async () => {
  for (const failure of ["write", "read", "socket", "websocket"]) {
    const fixture = socketFixture({ failWrite: failure === "write" });
    const server = new Endpoint();
    worker.bridge(server, fixture.socket);
    if (failure === "write") server.emit("message", binary(64));
    if (failure === "read") fixture.control().error(new Error("synthetic read failure"));
    if (failure === "socket") fixture.closed.reject(new Error("synthetic socket failure"));
    if (failure === "websocket") server.emit("error");
    await tick();
    server.emit("close");
    assert.equal(fixture.stats.close, 1, failure);
    assert.equal(server.closes.length, 1, failure);
    assert.equal(server.closes[0].code, 4002, failure);
    assert.equal(fixture.socket.readable.locked, false, failure);
    assert.equal(fixture.socket.writable.locked, false, failure);
  }
});

test("failed connection setup closes its socket before returning a safe error", async () => {
  const fixture = socketFixture({ opened: Promise.reject(new Error("synthetic connect failure")) });
  globalThis.workerConnect = () => fixture.socket;
  const response = await worker.default.fetch(request("dst=2001%3Ab28%3Af23d%3A%3A1&dc=4"));
  assert.equal(response.status, 502);
  assert.equal(fixture.stats.close, 1);
  assert.equal(response.body, "Telegram connection unavailable");
});

test("a late successful connect is rejected at the original deadline", async t => {
  const opened = deferred();
  const fixture = socketFixture({ opened: opened.promise });
  let clock = 1000;
  t.mock.method(performance, "now", () => clock);
  globalThis.workerConnect = () => fixture.socket;
  const result = worker.default.fetch(request());
  clock += 10000;
  opened.resolve();
  assert.equal((await result).status, 502);
  assert.equal(fixture.stats.close, 1);
});
