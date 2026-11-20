/// <reference lib="webworker" />
import {
  cleanupOutdatedCaches,
  createHandlerBoundToURL,
  precacheAndRoute,
} from 'workbox-precaching';
import type { PrecacheEntry } from 'workbox-precaching';
import { NavigationRoute, registerRoute } from 'workbox-routing';

import { SERVER_PATHS } from './app/pwa/serverPaths';

declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: (PrecacheEntry | string)[];
};

// A new version waits until a person agrees to reload: no clientsClaim() and
// no skipWaiting() on install. An entrant may be mid-upload and a judge
// mid-scoring, and every page is a lazy chunk, so the old precache has to
// keep serving the old chunks to the open tabs until they reload.
self.addEventListener('message', (event) => {
  const data: unknown = event.data;
  if (
    typeof data === 'object' &&
    data !== null &&
    'type' in data &&
    data.type === 'SKIP_WAITING'
  ) {
    void self.skipWaiting();
  }
});

precacheAndRoute(self.__WB_MANIFEST);
cleanupOutdatedCaches();

// Navigations get the precached app shell, except those the server answers.
// NavigationRoute tests each pattern against the path and query string, as
// isServerPath() does.
registerRoute(
  new NavigationRoute(createHandlerBoundToURL('/index.html'), {
    denylist: [...SERVER_PATHS],
  }),
);

// Nothing else is routed, so every other request (/api, /media, photographs
// on another origin) goes to the network and the HTTP cache. Caching them
// here would be wrong: the API answers per user and judging is anonymous, so
// a cached answer could reach the wrong person, and photographs on S3 have
// URLs signed for one hour.
