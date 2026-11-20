/**
 * The navigations that the service worker's navigation route
 * (navigationHandler.ts) leaves alone: the backend's paths, the paths nginx
 * serves files from, and any path with a file extension. Such a navigation
 * asks for a file, not for one of the application's pages, so the worker
 * must not answer it with the stored index.html when the network fails. A
 * file the worker precaches (a hashed asset, an icon, site.webmanifest) is
 * answered by the precache route; every other request goes to the network as
 * without a worker. Each pattern is matched against the path and query
 * string.
 *
 * The patterns are not nginx's locations in docker/default.conf. A path with
 * an extension below the root, such as /contest/1/a.jpg, is a file here, and
 * nginx answers it with the application; /apiary is a page here, and nginx
 * passes it to Django. Online the worker passes such a navigation to the
 * network, so nginx answers it in both cases; only offline does the worker's
 * choice show, as a network error or as the stored index.html.
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
  // A file: the last path segment has an extension (sw.js, an icon,
  // site.webmanifest). A dot in the query string does not count.
  /^[^?]*\.[A-Za-z0-9]+(\?|$)/,
];

/** Whether a navigation to `pathAndQuery` must reach the server. */
export function isServerPath(pathAndQuery: string): boolean {
  return SERVER_PATHS.some((pattern) => pattern.test(pathAndQuery));
}
