/**
 * The messages between the page and the service worker. Both src/sw.ts and
 * registerServiceWorker.ts import these types; each side validates what it
 * receives, because a worker or page of another release may send anything.
 *
 * - SKIP_WAITING: the page asks the waiting worker to take over. No reply.
 * - IS_SAME_BUILD: the page asks a waiting worker whether it may take over
 *   unasked, sending the URL of the page's entry script, with a MessagePort
 *   to answer on. The worker replies on that port with SAME_BUILD: whether
 *   the script's path is in its precache manifest, and whether any window of
 *   the site other than the asking page is open, controlled or not.
 */

export interface SkipWaitingMessage {
  type: 'SKIP_WAITING';
}

export interface IsSameBuildMessage {
  type: 'IS_SAME_BUILD';
  entryScriptUrl: string;
}

/** A page's message to the worker. */
export type PageMessage = SkipWaitingMessage | IsSameBuildMessage;

/** The worker's reply to IS_SAME_BUILD. */
export interface SameBuildReply {
  type: 'SAME_BUILD';
  sameBuild: boolean;
  /**
   * Whether another window may be open: true when one is, and when the
   * worker could not tell the asking page apart from the others.
   */
  otherWindows: boolean;
}
