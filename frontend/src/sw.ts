/// <reference lib="webworker" />
import {
  cleanupOutdatedCaches,
  matchPrecache,
  precacheAndRoute,
} from 'workbox-precaching';
import type { PrecacheEntry } from 'workbox-precaching';
import { registerRoute } from 'workbox-routing';

import {
  answerNavigation,
  handlesNavigation,
} from './app/pwa/navigationHandler';
import {
  handleWorkerMessage,
  precachedPaths,
} from './app/pwa/workerMessageHandler';

declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: (PrecacheEntry | string)[];
};

// The build replaces this one reference with the precache manifest.
const manifest = self.__WB_MANIFEST;
const paths = precachedPaths(manifest, self.location.href);

// A new version waits: no clientsClaim() and no skipWaiting() on install.
// Taking over deletes the previous version's precache, and nginx no longer
// has those files either, so a tab still running the previous version would
// fail on its next lazy page; an entrant may be mid-upload and a judge
// mid-scoring. A page asks the waiting worker whether it was built with that
// page and whether any other window of the site is open. Only a page of this
// build that is the site's one window lets the new version take over unasked;
// a page of this build with other windows open waits and asks again later. A
// page of the previous version offers a reload, and SKIP_WAITING then comes
// from a person who accepted it.
self.addEventListener('message', (event) => {
  const source = event.source;
  event.waitUntil(
    handleWorkerMessage(
      event.data,
      event.ports[0],
      source instanceof Client ? source.id : null,
      {
        skipWaiting: () => {
          void self.skipWaiting();
        },
        isPrecached: (path) => paths.has(path),
        windowClientIds: async () => {
          const windows = await self.clients.matchAll({
            type: 'window',
            includeUncontrolled: true,
          });
          return windows.map((client) => client.id);
        },
      },
    ),
  );
});

// Documents come from the network whenever it can be reached. nginx sends
// each document with a script policy whose nonce is new for every response,
// and a proxy (Cloudflare's bot detection) injects an inline script stamped
// with that nonce. Answering every load with one stored document would reuse
// one nonce and one copy of the proxy's script for as long as this version
// lives. The precached index.html is still there so that the app opens
// offline; the Cache API keeps that response with its own headers, so its
// policy and the nonce in its body still match.
//
// Registered before precacheAndRoute(), whose route would otherwise answer
// "/" with the precached index.html. Navigations to the paths in
// app/pwa/serverPaths.ts are not handled here: the precache route answers
// those it holds (an icon, site.webmanifest), and the rest reach the server
// as without a worker.
registerRoute(
  ({ request, url }) => handlesNavigation(request, url),
  ({ request }) =>
    answerNavigation(request, {
      fetch: (navigation) => fetch(navigation),
      precachedShell: () => matchPrecache('/index.html'),
    }),
);

precacheAndRoute(manifest);
cleanupOutdatedCaches();

// Nothing else is routed, so every other request (/api, /media, photographs
// on another origin) goes to the network and the HTTP cache. Caching them
// here would be wrong: the API answers per user and judging is anonymous, so
// a cached answer could reach the wrong person, and photographs on S3 have
// URLs signed for one hour.
