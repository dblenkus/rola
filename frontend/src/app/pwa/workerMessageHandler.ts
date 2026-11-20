/**
 * How the service worker handles the page's messages (workerMessages.ts). It
 * runs in the worker, so it touches no DOM-only or worker-only globals;
 * src/sw.ts passes in the worker's actions.
 */
import type { SameBuildReply } from './workerMessages';

/**
 * A precache manifest entry: a URL relative to the worker, with or without a
 * revision.
 */
export type ManifestEntry =
  string | { readonly url: string; readonly revision?: string | null };

/** The path names of the precache manifest's URLs, resolved against `base`. */
export function precachedPaths(
  manifest: readonly ManifestEntry[],
  base: string,
): ReadonlySet<string> {
  return new Set(
    manifest.map(
      (entry) =>
        new URL(typeof entry === 'string' ? entry : entry.url, base).pathname,
    ),
  );
}

/** What the worker does for a message. */
export interface WorkerActions {
  skipWaiting: () => void;
  /** Whether `path` is the path name of a precached URL. */
  isPrecached: (path: string) => boolean;
  /** The client ids of the site's windows, controlled or not. */
  windowClientIds: () => Promise<readonly string[]>;
}

/** Where a reply goes: the port the page sent with its message. */
export interface ReplyPort {
  postMessage: (message: SameBuildReply) => void;
}

function sameBuild(entryScriptUrl: string, actions: WorkerActions): boolean {
  let url: URL;
  // Not URL.canParse(), which Safari has only from version 17.
  try {
    url = new URL(entryScriptUrl);
  } catch {
    return false;
  }
  return actions.isPrecached(url.pathname);
}

/**
 * Whether a window other than the asker's is open. Without the asker's
 * client id, or when the windows cannot be listed, the answer is yes: the
 * asker's own window cannot be told apart from another one.
 */
async function otherWindows(
  askerId: string | null,
  actions: WorkerActions,
): Promise<boolean> {
  if (askerId === null) return true;
  let ids: readonly string[];
  try {
    ids = await actions.windowClientIds();
  } catch (error: unknown) {
    console.warn('Service worker could not list the windows', error);
    return true;
  }
  return ids.some((id) => id !== askerId);
}

/**
 * Handles one message from a page: SKIP_WAITING takes over, IS_SAME_BUILD is
 * answered on `port`. `askerId` is the client id of the page that sent the
 * message, or null if the message did not come from a client. Anything else,
 * and IS_SAME_BUILD without a port or a string URL, is ignored. Resolves once
 * the reply has been sent.
 */
export async function handleWorkerMessage(
  data: unknown,
  port: ReplyPort | undefined,
  askerId: string | null,
  actions: WorkerActions,
): Promise<void> {
  if (typeof data !== 'object' || data === null || !('type' in data)) return;
  if (data.type === 'SKIP_WAITING') {
    actions.skipWaiting();
    return;
  }
  if (
    data.type === 'IS_SAME_BUILD' &&
    port !== undefined &&
    'entryScriptUrl' in data &&
    typeof data.entryScriptUrl === 'string'
  ) {
    port.postMessage({
      type: 'SAME_BUILD',
      sameBuild: sameBuild(data.entryScriptUrl, actions),
      otherWindows: await otherWindows(askerId, actions),
    });
  }
}
