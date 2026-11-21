// The Pages Function in functions/[[path]].js, with fetch and env mocked.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../../functions/[[path]].js", import.meta.url), "utf8");
const { onRequest } = await import("data:text/javascript," + encodeURIComponent(source));

function run(request, env = { PROXY_SECRET: "s3cret" }) {
  const calls = [];
  globalThis.fetch = async (target, init) => {
    calls.push({ target: String(target), init });
    return new Response('{"status":"ok"}', {
      status: 200,
      headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
    });
  };
  const next = async () => new Response("static page");
  return onRequest({ request, next, env }).then((response) => ({ response, calls }));
}

test("relays an API request with only the headers the backend needs", async () => {
  const request = new Request("https://phishlens.dev/analyse?x=1", {
    method: "POST",
    body: '{"raw_text":"hello"}',
    headers: {
      cookie: "session=abc",
      authorization: "Bearer token",
      "x-phishlens-proxy": "forged",
      "x-forwarded-for": "198.51.100.9",
      "cf-connecting-ip": "203.0.113.7",
      "content-type": "application/json",
    },
  });
  const { response, calls } = await run(request);
  assert.equal(calls.length, 1);
  const { target, init } = calls[0];
  assert.equal(target, "https://phishlens-backend-1018549349863.europe-west1.run.app/analyse?x=1");
  assert.equal(init.headers.get("cookie"), null);
  assert.equal(init.headers.get("authorization"), null);
  assert.equal(init.headers.get("x-phishlens-proxy"), "s3cret");
  assert.equal(init.headers.get("x-forwarded-for"), "203.0.113.7");
  assert.equal(init.headers.get("content-type"), "application/json");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("strict-transport-security"), /max-age=31536000/);
  assert.equal(response.headers.get("referrer-policy"), "strict-origin-when-cross-origin");
  assert.equal(response.headers.get("access-control-allow-origin"), "*");
  assert.equal(await response.text(), '{"status":"ok"}');
});

test("a client-sent secret is dropped even without PROXY_SECRET", async () => {
  const request = new Request("https://phishlens.dev/health", {
    headers: { "x-phishlens-proxy": "forged", "x-forwarded-for": "198.51.100.9" },
  });
  const { calls } = await run(request, {});
  assert.equal(calls[0].init.headers.get("x-phishlens-proxy"), null);
  assert.equal(calls[0].init.headers.get("x-forwarded-for"), null);
});

test("BACKEND_ORIGIN overrides the default backend", async () => {
  const request = new Request("https://phishlens.dev/health");
  const { calls } = await run(request, { BACKEND_ORIGIN: "https://backend.example" });
  assert.equal(calls[0].target, "https://backend.example/health");
});

test("other methods get 405 without reaching the backend", async () => {
  for (const method of ["PUT", "DELETE", "PATCH"]) {
    const request = new Request("https://phishlens.dev/feedback", { method, body: "{}" });
    const { response, calls } = await run(request);
    assert.equal(response.status, 405, method);
    assert.equal(calls.length, 0);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.match(response.headers.get("allow"), /POST/);
  }
});

test("paths outside the API are left to the static site", async () => {
  const { response, calls } = await run(new Request("https://phishlens.dev/metrics"));
  assert.equal(calls.length, 0);
  assert.equal(await response.text(), "static page");
});
