/**
 * Registers the root-scoped service worker built from src/sw.ts and tracks
 * whether a new version waits for this tab to reload. The worker never takes
 * over by itself: this module lets it take over at once when the page was
 * built together with it and no other window of the site is open, and
 * applyUpdate() when a person accepts it.
 */
import { reloadPage } from './reloadPage';
import type { IsSameBuildMessage, SkipWaitingMessage } from './workerMessages';

// An installed app resumed from the app switcher makes no navigation, so the
// browser does not check sw.js by itself. One check a minute at most keeps
// that to a small request.
export const UPDATE_CHECK_INTERVAL_MS = 60 * 1000;

// How long a waiting worker has to say whether it may take over. A worker
// of an older version does not answer at all.
export const SAME_BUILD_TIMEOUT_MS = 2000;

// The new version's worker, once it waits while an older one controls this
// tab; it stays set after the worker activates, until the reload.
let updateWorker: ServiceWorker | null = null;
// The worker whose update the person put off with Later.
let dismissedWorker: ServiceWorker | null = null;
// The person accepted the update in this tab, so the takeover reloads it.
let updateAccepted = false;
// The waiting worker being asked whether it may take over.
let askedWorker: ServiceWorker | null = null;
let reloading = false;
const listeners = new Set<() => void>();

/** Whether to offer a new version: one waits and was not put off. */
export function isUpdateReady(): boolean {
  return updateWorker !== null && updateWorker !== dismissedWorker;
}

/** Calls `listener` when isUpdateReady() may have changed. */
export function subscribeToUpdate(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function notify(): void {
  for (const listener of listeners) listener();
}

function setUpdateWorker(worker: ServiceWorker): void {
  if (worker === updateWorker) return;
  updateWorker = worker;
  notify();
}

/** Puts the waiting version off until the next one, or the next page load. */
export function dismissUpdate(): void {
  dismissedWorker = updateWorker;
  notify();
}

function reloadOnce(): void {
  if (reloading) return;
  reloading = true;
  reloadPage();
}

/**
 * Lets the waiting version take over and reloads this tab once it has. Other
 * tabs keep running until their own person reloads them. In a tab where the
 * new version already took over (accepted in another tab), it only reloads.
 */
export function applyUpdate(): void {
  const worker = updateWorker;
  if (worker === null) return;
  if (worker.state === 'activating' || worker.state === 'activated') {
    reloadOnce();
    return;
  }
  updateAccepted = true;
  skipWaiting(worker);
}

function skipWaiting(worker: ServiceWorker): void {
  const message: SkipWaitingMessage = { type: 'SKIP_WAITING' };
  worker.postMessage(message);
}

/**
 * The URL of this page's entry script: the one module script under /assets/
 * that the build puts into index.html. Null if there is not exactly one.
 */
function entryScriptUrl(): string | null {
  const scripts = Array.from(
    document.querySelectorAll<HTMLScriptElement>('script[type="module"][src]'),
  ).filter((script) => new URL(script.src).pathname.startsWith('/assets/'));
  const [script] = scripts;
  return scripts.length === 1 && script !== undefined ? script.src : null;
}

/**
 * What to do with a waiting worker: let it take over unasked, leave it
 * waiting and ask again at the next update check, or offer the update.
 */
type WaitingWorkerAction = 'takeOver' | 'askLater' | 'offer';

/** The action for the worker's reply to IS_SAME_BUILD. */
function actionForReply(data: unknown): WaitingWorkerAction {
  if (
    typeof data !== 'object' ||
    data === null ||
    !('type' in data) ||
    data.type !== 'SAME_BUILD' ||
    !('sameBuild' in data) ||
    data.sameBuild !== true
  ) {
    return 'offer';
  }
  // Only an answer that no other window is open lets it take over: another
  // window may still run the previous version, whose files the takeover
  // deletes.
  return 'otherWindows' in data && data.otherWindows === false
    ? 'takeOver'
    : 'askLater';
}

/**
 * Asks `worker` whether its precache holds this page's entry script, that is
 * whether this page already runs its version, and whether another window of
 * the site is open. Resolves 'offer' when the page has no entry script or
 * the worker gives no valid answer in time.
 */
function askWaitingWorker(worker: ServiceWorker): Promise<WaitingWorkerAction> {
  const url = entryScriptUrl();
  if (url === null) return Promise.resolve('offer');
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    const finish = (action: WaitingWorkerAction) => {
      clearTimeout(timeout);
      channel.port1.close();
      resolve(action);
    };
    const timeout = setTimeout(() => {
      finish('offer');
    }, SAME_BUILD_TIMEOUT_MS);
    channel.port1.onmessage = (event: MessageEvent<unknown>) => {
      finish(actionForReply(event.data));
    };
    const message: IsSameBuildMessage = {
      type: 'IS_SAME_BUILD',
      entryScriptUrl: url,
    };
    worker.postMessage(message, [channel.port2]);
  });
}

/**
 * Handles a worker that waits while another one controls this tab. A page
 * loaded from the network after a release already runs the new version and
 * has every file the new precache holds, so when it is the site's only window
 * the worker takes over without a prompt or a reload. While other windows are
 * open, one of them may run the previous version, so nothing happens until
 * the next update check asks again. A page of the previous version offers
 * the update.
 */
function onWaitingWorker(worker: ServiceWorker): void {
  if (worker === updateWorker || worker === askedWorker) return;
  askedWorker = worker;
  void askWaitingWorker(worker).then((action) => {
    if (askedWorker === worker) askedWorker = null;
    if (action === 'takeOver') {
      skipWaiting(worker);
    } else if (action === 'offer') {
      setUpdateWorker(worker);
    }
  });
}

/** Handles the worker that already waits, if any, in a controlled tab. */
function checkWaitingWorker(registration: ServiceWorkerRegistration): void {
  if (
    registration.waiting !== null &&
    navigator.serviceWorker.controller !== null
  ) {
    onWaitingWorker(registration.waiting);
  }
}

// A worker that waits while another one controls this tab is a new version.
// On the first install nothing controls the tab, the tab already runs the
// newest version, and the worker activates without waiting. A tab loaded
// with a forced reload is not controlled either and came from the network.
function watchForUpdates(registration: ServiceWorkerRegistration): void {
  const container = navigator.serviceWorker;
  checkWaitingWorker(registration);
  registration.addEventListener('updatefound', () => {
    const worker = registration.installing;
    if (worker === null) return;
    worker.addEventListener('statechange', () => {
      if (worker.state === 'installed' && container.controller !== null) {
        onWaitingWorker(worker);
      }
    });
  });
}

/**
 * Checks for a new worker when the page is shown again or the window gets
 * focus, at most once a minute, and asks a worker that already waits again
 * whether it may take over. Focus covers a desktop tab that stays visible.
 * Returns a function that removes the listeners.
 */
export function checkForUpdatesWhenShown(
  registration: ServiceWorkerRegistration,
): () => void {
  // The navigation that loaded the page already made the browser check.
  let lastCheck = Date.now();
  const check = () => {
    // Wall-clock time, so time spent suspended counts.
    if (Date.now() - lastCheck < UPDATE_CHECK_INTERVAL_MS) return;
    lastCheck = Date.now();
    // A worker that waits for other windows to close is asked again.
    checkWaitingWorker(registration);
    registration.update().catch((error: unknown) => {
      // Offline or the server is down: the current worker stays.
      console.warn('Service worker update check failed', error);
    });
  };
  const onVisibilityChange = () => {
    if (document.visibilityState === 'visible') check();
  };
  document.addEventListener('visibilitychange', onVisibilityChange);
  window.addEventListener('focus', check);
  return () => {
    document.removeEventListener('visibilitychange', onVisibilityChange);
    window.removeEventListener('focus', check);
  };
}

/**
 * Registers /sw.js for the whole site once the page has loaded, so the
 * worker's precaching does not compete with the page's own requests. Without
 * service worker support the app runs without one. A failed registration is
 * logged and the app runs on without the worker.
 */
export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator)) return;
  const container = navigator.serviceWorker;
  container.addEventListener('controllerchange', () => {
    if (updateAccepted) reloadOnce();
  });
  window.addEventListener('load', () => {
    container.register('/sw.js', { scope: '/' }).then(
      (registration) => {
        watchForUpdates(registration);
        checkForUpdatesWhenShown(registration);
      },
      (error: unknown) => {
        console.error('Service worker registration failed', error);
      },
    );
  });
}
