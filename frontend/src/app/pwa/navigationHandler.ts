/**
 * How the service worker answers a navigation. It runs in the worker, so it
 * touches no DOM-only or worker-only globals; src/sw.ts passes in the fetch
 * and the precache lookup.
 */
import { isServerPath } from './serverPaths';

export interface NavigationSources {
  /** The network, as the worker's fetch. */
  fetch: (request: Request) => Promise<Response>;
  /** The precached index.html, or undefined if the precache lacks it. */
  precachedShell: () => Promise<Response | undefined>;
}

// The document's own address. It has a file extension, so serverPaths.ts
// counts it as a server path, but it is the application's page, and the
// precache route would answer it with the stored copy if this one did not.
const DOCUMENT_PATH = '/index.html';

/**
 * Whether the worker answers this request: a navigation to one of the
 * application's pages. Navigations to the paths in serverPaths.ts are left to
 * the browser and the server.
 */
export function handlesNavigation(
  request: { readonly mode: RequestMode },
  url: URL,
): boolean {
  return (
    request.mode === 'navigate' &&
    (url.pathname === DOCUMENT_PATH || !isServerPath(url.pathname + url.search))
  );
}

/**
 * Answers a navigation with the network's response, whatever its status, and
 * only when the network cannot be reached with the precached index.html, or
 * an error response if the precache lacks it. There is no timeout: a slow
 * network waits, as it would without a worker.
 */
export async function answerNavigation(
  request: Request,
  sources: NavigationSources,
): Promise<Response> {
  try {
    return await sources.fetch(request);
  } catch {
    return (await sources.precachedShell()) ?? Response.error();
  }
}
