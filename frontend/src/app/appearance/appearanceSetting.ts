// The person's choice of appearance, remembered in this browser. "System"
// follows the device and is stored as no key; light and dark are stored by
// name and force that theme through `data-theme` on <html>, which the design
// tokens read.
//
// public/appearance.js reads the same key before the first paint. An
// installed service worker can serve an older copy of that file to a newer
// page, so the key and the two stored values never change.
export type Appearance = 'system' | 'light' | 'dark';

export const appearances: readonly Appearance[] = ['system', 'light', 'dark'];

const key = 'rola.appearance';

function parseStored(value: string | null): Appearance | undefined {
  if (value === null) return 'system';
  return value === 'light' || value === 'dark' ? value : undefined;
}

// A browser that blocks site data throws on every access to its storage; the
// page then follows the device.
export function loadAppearance(): Appearance {
  try {
    return parseStored(localStorage.getItem(key)) ?? 'system';
  } catch {
    return 'system';
  }
}

// Only these two values are ever written to the attribute: any other value
// would make the tokens show the light theme on a dark device.
export function applyAppearance(choice: Appearance): void {
  const root = document.documentElement;
  if (choice === 'system') root.removeAttribute('data-theme');
  else root.dataset.theme = choice;
}

// The choice this page shows. It is read from storage on first use and on
// start, and set by storeAppearance and by other tabs; with blocked storage
// it is the only record of the choice, which then lasts while the page is
// open.
let current: Appearance | undefined;
const listeners = new Set<() => void>();

function setCurrent(choice: Appearance): void {
  current = choice;
  applyAppearance(choice);
  listeners.forEach((listener) => listener());
}

export function getAppearance(): Appearance {
  current ??= loadAppearance();
  return current;
}

export function subscribeAppearance(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function storeAppearance(choice: Appearance): void {
  try {
    if (choice === 'system') localStorage.removeItem(key);
    else localStorage.setItem(key, choice);
  } catch {
    // Blocked storage keeps the choice for this page only.
  }
  setCurrent(choice);
}

// A choice made in another tab of this browser. `key` is null when that tab
// cleared the whole storage, which leaves no choice.
function onStorage(event: StorageEvent): void {
  if (event.key !== key && event.key !== null) return;
  try {
    if (event.storageArea !== localStorage) return;
  } catch {
    return;
  }
  const choice = parseStored(event.key === null ? null : event.newValue);
  if (choice !== undefined) setCurrent(choice);
}

// A page restored from the back/forward cache was frozen and missed the
// storage events of the choices made meanwhile, so it reads the choice again.
function onPageShow(event: PageTransitionEvent): void {
  if (event.persisted) setCurrent(loadAppearance());
}

// Applies the stored choice again, in case public/appearance.js failed or is
// an older copy, and follows the choices made in other tabs. main.tsx calls it
// once before rendering; it returns the function that stops following them.
export function startAppearance(): () => void {
  setCurrent(loadAppearance());
  window.addEventListener('storage', onStorage);
  window.addEventListener('pageshow', onPageShow);
  return () => {
    window.removeEventListener('storage', onStorage);
    window.removeEventListener('pageshow', onPageShow);
  };
}
