/**
 * Cloudflare Worker relay for anonymous WARP registration.
 *
 * The phone sends only its public key. The private key never leaves the device.
 * The Worker performs the Cloudflare API call from Cloudflare's network, where
 * `api.cloudflareclient.com` is not filtered by SNI.
 *
 * Deploy with `wrangler deploy` or paste this file into the Workers dashboard.
 * Set the `RELAY_TOKEN` secret; without it every request is rejected.
 */

const API_URL = "https://api.cloudflareclient.com/v0a4471/reg";
const CLIENT_VERSION = "a-6.35-4471";
const MAX_BODY_BYTES = 4096;
const RATE_LIMIT_MS = 2000;

// Best-effort per-isolate limiter. It is not a security boundary: the token is.
const lastSeen = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return new Response("ok\n", {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    if (url.pathname !== "/register") {
      return json({ error: "not found" }, 404);
    }

    if (request.method !== "POST") {
      return json({ error: "method not allowed" }, 405, { Allow: "POST" });
    }

    if (!authorized(request, env)) {
      return json({ error: "invalid relay token" }, 401);
    }

    if (rateLimited(request)) {
      return json({ error: "too many requests" }, 429);
    }

    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) {
      return json({ error: "request body is too large" }, 413);
    }

    let input;
    try {
      input = JSON.parse(raw);
    } catch {
      return json({ error: "invalid JSON" }, 400);
    }

    const publicKey = text(input.public_key).trim();
    if (!isWireGuardKey(publicKey)) {
      return json({ error: "public_key must be a 32-byte base64 key" }, 400);
    }

    const locale = truncate(text(input.locale).trim(), "en-US", 32);
    const model = truncate(text(input.model).trim(), "PC", 64);

    let upstream;
    try {
      upstream = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "User-Agent": "WARP for Android",
          "CF-Client-Version": CLIENT_VERSION,
          "Accept": "application/json",
        },
        body: JSON.stringify({
          key: publicKey,
          install_id: "",
          fcm_token: "",
          tos: cloudflareTime(),
          model,
          serial_number: randomHex(8),
          os_version: "",
          key_type: "curve25519",
          tunnel_type: "wireguard",
          locale,
        }),
      });
    } catch (error) {
      return json({ error: `upstream request failed: ${error}` }, 502);
    }

    const body = await upstream.text();
    if (!upstream.ok) {
      return new Response(body.slice(0, 2048), {
        status: 502,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      });
    }

    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  },
};

function authorized(request, env) {
  const expected = text(env.RELAY_TOKEN).trim();
  if (expected === "") {
    // Fail closed: a Worker deployed without a token must not become an open
    // registration relay.
    return false;
  }
  const provided = text(request.headers.get("X-Relay-Token")).trim();
  return constantTimeEqual(provided, expected);
}

function rateLimited(request) {
  const address = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const previous = lastSeen.get(address) || 0;
  if (now - previous < RATE_LIMIT_MS) {
    return true;
  }
  lastSeen.set(address, now);

  if (lastSeen.size > 4096) {
    for (const [key, seen] of lastSeen) {
      if (now - seen > 10 * 60_000) {
        lastSeen.delete(key);
      }
    }
  }
  return false;
}

function isWireGuardKey(value) {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    return false;
  }
  try {
    return atob(value).length === 32;
  } catch {
    return false;
  }
}

function cloudflareTime() {
  // The WARP client sends milliseconds and a numeric offset, not the "Z" form.
  return new Date().toISOString().replace("Z", "+00:00");
}

function randomHex(bytes) {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function truncate(value, fallback, limit) {
  return (value || fallback).slice(0, limit);
}

function text(value) {
  return typeof value === "string" ? value : "";
}

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.length; index++) {
    difference |= a[index] ^ b[index];
  }
  return difference === 0;
}

function json(payload, status, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}
