import { connect } from "cloudflare:sockets";

// Keep this catalogue aligned with proxy/route_policy.py. No DNS destinations:
// a Worker is a Telegram relay, not an unrestricted outbound TCP proxy.
export const TELEGRAM_CIDRS = Object.freeze([
  "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22",
  "91.108.16.0/22", "91.108.12.0/22", "149.154.160.0/20",
  "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
  "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48",
  "2001:b28:f23c::/48", "2a0a:f280::/32",
]);
export const MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
export const MAX_PENDING_BYTES = 4 * 1024 * 1024;
export const MAX_PENDING_MESSAGES = 64;
const TCP_CHUNK_BYTES = 64 * 1024;
const CONNECT_TIMEOUT_MS = 10000;

function parseAddress(value) {
  if (typeof value !== "string" || value.length > 39) return null;
  if (value.includes(".")) {
    const parts = value.split(".");
    if (parts.length !== 4 || parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return null;
    return { bits: 32, number: parts.reduce((number, part) => (number << 8n) | BigInt(part), 0n) };
  }
  if (!/^[0-9a-f:]+$/i.test(value) || value.split("::").length > 2) return null;
  const halves = value.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if ([...left, ...right].some(part => !/^[0-9a-f]{1,4}$/i.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const parts = [...left, ...Array(missing).fill("0"), ...right];
  return { bits: 128, number: parts.reduce((number, part) => (number << 16n) | BigInt("0x" + part), 0n) };
}

const networks = TELEGRAM_CIDRS.map(cidr => {
  const [address, prefix] = cidr.split("/");
  const parsed = parseAddress(address);
  return { ...parsed, shift: BigInt(parsed.bits - Number(prefix)) };
});

export function isTelegramDestination(value) {
  const address = parseAddress(value);
  return address !== null && networks.some(network => address.bits === network.bits &&
    (address.number >> network.shift) === (network.number >> network.shift));
}

function ignoreFailure(operation) {
  try { Promise.resolve(operation()).catch(() => {}); } catch {}
}

// EventTarget does not await async listeners. Keep one writer and count both
// queued and in-flight messages until write() settles, including tiny frames.
export function bridge(server, socket) {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let stopped = false;
  let writing = false;
  let pendingBytes = 0;
  let pendingMessages = 0;
  const queue = [];
  const releaseWriter = () => { try { writer.releaseLock(); } catch {} };
  function stop(code = 1000, reason = "") {
    if (stopped) return;
    stopped = true;
    queue.length = 0;
    pendingBytes = pendingMessages = 0;
    try { server.close(code, reason); } catch {}
    ignoreFailure(() => socket.close());
    ignoreFailure(() => reader.cancel());
    ignoreFailure(() => writer.abort().finally(releaseWriter));
  }
  async function drain() {
    if (writing || stopped) return;
    writing = true;
    try {
      while (!stopped && queue.length) {
        const data = queue.shift();
        await writer.write(data);
        if (stopped) return;
        pendingBytes -= data.byteLength;
        pendingMessages--;
      }
    } catch {
      stop(4002, "TCP write failed");
    } finally {
      writing = false;
    }
  }
  server.addEventListener("message", event => {
    if (stopped) return;
    // binaryType is set before accept(); text and unexpected Blob values fail
    // closed rather than introducing asynchronous conversions/reordering.
    if (!(event.data instanceof ArrayBuffer) || event.data.byteLength === 0 ||
        event.data.byteLength > MAX_MESSAGE_BYTES) {
      stop(4001, "Invalid binary message");
      return;
    }
    if (pendingBytes + event.data.byteLength > MAX_PENDING_BYTES || pendingMessages >= MAX_PENDING_MESSAGES) {
      stop(4001, "Upload queue limit");
      return;
    }
    pendingBytes += event.data.byteLength;
    pendingMessages++;
    queue.push(new Uint8Array(event.data));
    void drain();
  });
  server.addEventListener("close", () => stop());
  server.addEventListener("error", () => stop(4002, "WebSocket failed"));
  void (async () => {
    try {
      while (!stopped) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) throw new Error("Invalid TCP data");
        for (let offset = 0; !stopped && offset < value.byteLength; offset += TCP_CHUNK_BYTES) {
          server.send(value.subarray(offset, offset + TCP_CHUNK_BYTES));
        }
      }
      stop();
    } catch {
      stop(4002, "TCP read failed");
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  })();
  // Socket.closed can reject independently of a readable/writable operation.
  Promise.resolve(socket.closed).catch(() => stop(4002, "TCP socket failed"));
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/apiws") return new Response("Not found", { status: 404 });
    if (request.method !== "GET" || (request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket GET", { status: 426 });
    }
    const destinations = url.searchParams.getAll("dst");
    const dcs = url.searchParams.getAll("dc");
    if (destinations.length !== 1 || !isTelegramDestination(destinations[0]) || dcs.length > 1 ||
        (dcs.length === 1 && !/^(1|2|3|4|5|203)$/.test(dcs[0]))) {
      return new Response("Invalid Telegram destination", { status: 400 });
    }
    const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "").split(",").map(value => value.trim());
    if (!protocols.includes("binary")) return new Response("Expected binary subprotocol", { status: 400 });
    let socket;
    let timer;
    const deadline = performance.now() + CONNECT_TIMEOUT_MS;
    try {
      socket = connect({ hostname: destinations[0], port: 443 });
      Promise.resolve(socket.closed).catch(() => {});
      await Promise.race([
        socket.opened,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Connection deadline")), CONNECT_TIMEOUT_MS); }),
      ]);
      // An event-loop stall must not turn a late successful connect into an
      // admission after the same deadline used by the timeout callback.
      if (performance.now() >= deadline) throw new Error("Connection deadline");
      clearTimeout(timer);
      const pair = new WebSocketPair();
      const server = pair[1];
      server.binaryType = "arraybuffer";
      server.accept();
      bridge(server, socket);
      return new Response(null, { status: 101, headers: { "Sec-WebSocket-Protocol": "binary" }, webSocket: pair[0] });
    } catch {
      clearTimeout(timer);
      if (socket) ignoreFailure(() => socket.close());
      return new Response("Telegram connection unavailable", { status: 502 });
    }
  },
};
