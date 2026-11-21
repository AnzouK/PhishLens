// Cloudflare Pages Function: phishlens.dev serves the website from Pages and
// forwards the API paths to the backend on Google Cloud Run. The extension and
// the website keep calling https://phishlens.dev, as with the old server.
//
// Only the paths in site/_routes.json reach this function; everything else is
// a static file. /metrics is never forwarded.

const BACKEND = "https://phishlens-backend-1018549349863.europe-west1.run.app";

const API = new Set([
  "/analyse",
  "/analyse_attachment",
  "/explain",
  "/feedback",
  "/health",
  "/reputation/stats",
]);

export async function onRequest({ request, next, env }) {
  const url = new URL(request.url);
  if (!API.has(url.pathname)) return next();

  const target = new URL(url.pathname + url.search, env.BACKEND_ORIGIN || BACKEND);
  const headers = new Headers(request.headers);
  headers.delete("host");
  // The client address Cloudflare saw replaces whatever X-Forwarded-For the
  // client sent, so the backend's per-address rate limits cannot be dodged
  // by forging that header.
  const client = request.headers.get("cf-connecting-ip");
  if (client) headers.set("x-forwarded-for", client);
  else headers.delete("x-forwarded-for");
  // Shared secret that proves to the backend the request came through
  // this function (PROXY_SECRET on both sides). A client-sent value is
  // never forwarded.
  headers.delete("x-phishlens-proxy");
  if (env.PROXY_SECRET) headers.set("x-phishlens-proxy", env.PROXY_SECRET);

  const hasBody = !["GET", "HEAD"].includes(request.method);
  const response = await fetch(target, {
    method: request.method,
    headers,
    body: hasBody ? request.body : undefined,
    redirect: "manual",
  });
  return new Response(response.body, response);
}
