/**
 * The navigations the service worker leaves to the server instead of
 * answering them with the precached index.html. Each pattern is matched
 * against the path and query string, as Workbox's NavigationRoute denylist
 * is. Keep the prefixes in step with the locations in docker/default.conf
 * and the development proxy in vite.config.ts.
 */
export const SERVER_PATHS: readonly RegExp[] = [
  // The API and the Django admin, proxied to Django.
  /^\/api(\/|\?|$)/,
  /^\/django-admin(\/|\?|$)/,
  // Uploaded photographs and Django's static files, served by nginx.
  /^\/media(\/|\?|$)/,
  /^\/static2(\/|\?|$)/,
  // The build's hashed files: a missing one must be a 404, not the app.
  /^\/assets(\/|\?|$)/,
  // A file: the last path segment has an extension (sw.js, an icon, the
  // manifest). A dot in the query string does not count.
  /^[^?]*\.[A-Za-z0-9]+(\?|$)/,
];

/** Whether a navigation to `pathAndQuery` must reach the server. */
export function isServerPath(pathAndQuery: string): boolean {
  return SERVER_PATHS.some((pattern) => pattern.test(pathAndQuery));
}
