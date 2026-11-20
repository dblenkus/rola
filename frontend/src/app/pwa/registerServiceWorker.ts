/**
 * Registers the root-scoped service worker built from src/sw.ts and tracks
 * whether a new version waits for this tab to reload. The worker never takes
 * over by itself; applyUpdate() asks it to.
 */
import { reloadPage } from './reloadPage';

// An installed app resumed from the app switcher makes no navigation, so the
// browser does not check sw.js by itself. One check a minute at most keeps
// that to a small request.
export const UPDATE_CHECK_INTERVAL_MS = 60 * 1000;

// The new version's worker, once it waits while an older one controls this
// tab; it stays set after the worker activates, until the reload.
let updateWorker: ServiceWorker | null = null;
// The worker whose update the person put off with Later.
let dismissedWorker: ServiceWorker | null = null;
// The person accepted the update in this tab, so the takeover reloads it.
let updateAccepted = false;
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
  worker.postMessage({ type: 'SKIP_WAITING' });
}

// A worker that waits while another one controls this tab is a new version.
// On the first install nothing controls the tab, the tab already runs the
// newest version, and the worker activates without waiting. A tab loaded
// with a forced reload is not controlled either and came from the network.
function watchForUpdates(registration: ServiceWorkerRegistration): void {
  const container = navigator.serviceWorker;
  if (registration.waiting !== null && container.controller !== null) {
    setUpdateWorker(registration.waiting);
  }
  registration.addEventListener('updatefound', () => {
    const worker = registration.installing;
    if (worker === null) return;
    worker.addEventListener('statechange', () => {
      if (worker.state === 'installed' && container.controller !== null) {
        setUpdateWorker(worker);
      }
    });
  });
}

/**
 * Checks for a new worker when the page is shown again or the window gets
 * focus, at most once a minute. Focus covers a desktop tab that stays
 * visible. Returns a function that removes the listeners.
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
