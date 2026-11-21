// Cloudflare Pages Function: phishlens.dev serves the website from Pages and
// forwards the API paths to the backend on Google Cloud Run. The extension and
// the website keep calling https://phishlens.dev, as with the old server.
//
// Only the paths in site/_routes.json reach this function; everything else is
// a static file. /metrics is never forwarded.

// Not a secret: the backend answers only requests carrying PROXY_SECRET.
// BACKEND_ORIGIN (a Pages variable) overrides it.
const BACKEND = "https://phishlens-backend-1018549349863.europe-west1.run.app";

const API = new Set([
  "/analyse",
  "/analyse_attachment",
  "/explain",
  "/feedback",
  "/health",
  "/reputation/stats",
]);

const METHODS = new Set(["GET", "HEAD", "POST", "OPTIONS"]);

// site/_headers does not apply to a Function's responses: the same values
// are set here on every answer relayed from the backend.
const SECURITY_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
};

// Never sent to the backend: it uses no cookies and no Authorization, and a
// client-sent X-PhishLens-Proxy must not pass for the function's own.
const DROPPED_REQUEST_HEADERS = ["host", "cookie", "authorization", "x-phishlens-proxy"];

function withSecurityHeaders(body, init) {
  const headers = new Headers(init.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(body, { status: init.status, statusText: init.statusText, headers });
}

export async function onRequest({ request, next, env }) {
  const url = new URL(request.url);
  if (!API.has(url.pathname)) return next();
  if (!METHODS.has(request.method)) {
    return withSecurityHeaders(JSON.stringify({ detail: "Method not allowed." }), {
      status: 405,
      headers: { allow: [...METHODS].join(", "), "content-type": "application/json" },
    });
  }

  const target = new URL(url.pathname + url.search, env.BACKEND_ORIGIN || BACKEND);
  const headers = new Headers(request.headers);
  for (const name of DROPPED_REQUEST_HEADERS) headers.delete(name);
  // The client address Cloudflare saw replaces whatever X-Forwarded-For the
  // client sent, so the backend's per-address rate limits cannot be dodged
  // by forging that header.
  const client = request.headers.get("cf-connecting-ip");
  if (client) headers.set("x-forwarded-for", client);
  else headers.delete("x-forwarded-for");
  // Shared secret that proves to the backend the request came through
  // this function (PROXY_SECRET on both sides).
  if (env.PROXY_SECRET) headers.set("x-phishlens-proxy", env.PROXY_SECRET);

  const hasBody = !["GET", "HEAD"].includes(request.method);
  const response = await fetch(target, {
    method: request.method,
    headers,
    body: hasBody ? request.body : undefined,
    redirect: "manual",
  });
  return withSecurityHeaders(response.body, response);
}
