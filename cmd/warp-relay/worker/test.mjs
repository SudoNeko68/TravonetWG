import assert from "node:assert/strict";
import worker from "./warp-relay.js";

const PUBLIC_KEY = btoa(String.fromCharCode(...new Uint8Array(32)));
const API_RESPONSE = JSON.stringify({
  config: { peers: [{ public_key: "peer-key" }] },
});

let lastRequest = null;
globalThis.fetch = async (url, options) => {
  lastRequest = { url, options };
  return new Response(API_RESPONSE, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};

function request(path, { method = "POST", token = "secret", ip = "203.0.113.1", body } = {}) {
  const headers = {};
  if (token !== null) headers["X-Relay-Token"] = token;
  if (ip !== null) headers["CF-Connecting-IP"] = ip;
  return new Request(`https://relay.example${path}`, {
    method,
    headers,
    body: method === "GET" ? undefined : body ?? "{}",
  });
}

const env = { RELAY_TOKEN: "secret" };

// Health check does not need a token.
let response = await worker.fetch(request("/healthz", { method: "GET", token: null }), env);
assert.equal(response.status, 200);

// Missing token is rejected.
response = await worker.fetch(request("/register", { token: null }), { RELAY_TOKEN: "secret" });
assert.equal(response.status, 401);

// Deployed without a secret: fail closed.
response = await worker.fetch(request("/register"), {});
assert.equal(response.status, 401);

// Wrong method.
response = await worker.fetch(request("/register", { method: "GET", ip: "203.0.113.2" }), env);
assert.equal(response.status, 405);

// Invalid public key.
response = await worker.fetch(
  request("/register", { ip: "203.0.113.3", body: JSON.stringify({ public_key: "AAAA" }) }),
  env,
);
assert.equal(response.status, 400);

// Happy path.
response = await worker.fetch(
  request("/register", {
    ip: "203.0.113.4",
    body: JSON.stringify({ public_key: PUBLIC_KEY, locale: "ru-RU", model: "Pixel 6" }),
  }),
  env,
);
assert.equal(response.status, 200);
assert.equal(await response.text(), API_RESPONSE);

assert.equal(lastRequest.url, "https://api.cloudflareclient.com/v0a4471/reg");
assert.equal(lastRequest.options.headers["CF-Client-Version"], "a-6.35-4471");
assert.equal(lastRequest.options.headers["User-Agent"], "WARP for Android");

const sent = JSON.parse(lastRequest.options.body);
assert.equal(sent.key, PUBLIC_KEY);
assert.equal(sent.locale, "ru-RU");
assert.equal(sent.model, "Pixel 6");
assert.equal(sent.key_type, "curve25519");
assert.equal(sent.tunnel_type, "wireguard");
assert.match(sent.serial_number, /^[0-9a-f]{16}$/);
assert.match(sent.tos, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$/);

// The same address is limited for two seconds.
response = await worker.fetch(
  request("/register", { ip: "203.0.113.4", body: JSON.stringify({ public_key: PUBLIC_KEY }) }),
  env,
);
assert.equal(response.status, 429);

// Upstream failure is reported as 502.
globalThis.fetch = async () =>
  new Response(JSON.stringify({ result: null, success: false }), { status: 401 });
response = await worker.fetch(
  request("/register", { ip: "203.0.113.5", body: JSON.stringify({ public_key: PUBLIC_KEY }) }),
  env,
);
assert.equal(response.status, 502);

console.log("worker tests passed");
