// The judge's choice to turn the keyboard shortcuts off, kept for the raters
// opened later. Only "off" is stored; the shortcuts are on without it.
const key = 'rola.judge.shortcuts';

// A browser that blocks site data throws on every access to its storage; the
// shortcuts are then on in each new rater, and the choice lasts while it is
// open.
export function loadShortcutsOn(): boolean {
  try {
    return localStorage.getItem(key) !== 'off';
  } catch {
    return true;
  }
}

export function storeShortcutsOn(on: boolean): void {
  try {
    if (on) localStorage.removeItem(key);
    else localStorage.setItem(key, 'off');
  } catch {
    // Blocked storage keeps the choice for this rater only.
  }
}
