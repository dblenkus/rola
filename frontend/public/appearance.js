// Applies the stored appearance before the first paint. index.html links this
// classic script ahead of the app, because the Content-Security-Policy allows
// no inline script. src/app/appearance/ writes the choice and applies it again
// when the app starts.
//
// An installed service worker can serve an older copy of this file to a newer
// page, so its contract never changes: the key 'rola.appearance' holds
// 'light' or 'dark', and anything else, including no key, leaves the page to
// follow the device.

try {
  const choice = localStorage.getItem('rola.appearance');
  if (choice === 'light' || choice === 'dark') {
    document.documentElement.dataset.theme = choice;
  }
} catch {
  // Blocked storage: the page follows the device.
}
