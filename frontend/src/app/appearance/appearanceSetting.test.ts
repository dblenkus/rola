import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  applyAppearance,
  getAppearance,
  loadAppearance,
  startAppearance,
  storeAppearance,
  subscribeAppearance,
} from './appearanceSetting';

const theme = () => document.documentElement.getAttribute('data-theme');

let stop = () => {};

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  stop = startAppearance();
});

afterEach(() => {
  stop();
  vi.restoreAllMocks();
});

function blockStorage() {
  const blocked = () => {
    throw new DOMException('Blocked', 'SecurityError');
  };
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(blocked);
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(blocked);
  vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(blocked);
}

function otherTab(key: string | null, newValue: string | null) {
  window.dispatchEvent(
    new StorageEvent('storage', { key, newValue, storageArea: localStorage }),
  );
}

describe('the stored appearance', () => {
  it('follows the device until a theme is chosen', () => {
    expect(loadAppearance()).toBe('system');
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });

  it('stores light and dark and sets the attribute', () => {
    storeAppearance('dark');
    expect(localStorage.getItem('rola.appearance')).toBe('dark');
    expect(theme()).toBe('dark');
    expect(loadAppearance()).toBe('dark');
    storeAppearance('light');
    expect(localStorage.getItem('rola.appearance')).toBe('light');
    expect(theme()).toBe('light');
    expect(getAppearance()).toBe('light');
  });

  it('removes the key and the attribute for system', () => {
    storeAppearance('dark');
    storeAppearance('system');
    expect(localStorage.getItem('rola.appearance')).toBeNull();
    expect(theme()).toBeNull();
    expect(getAppearance()).toBe('system');
  });

  it('reads an unknown stored value as system', () => {
    localStorage.setItem('rola.appearance', 'system');
    expect(loadAppearance()).toBe('system');
    localStorage.setItem('rola.appearance', 'Dark');
    expect(loadAppearance()).toBe('system');
  });

  it('never writes a value other than light or dark to the attribute', () => {
    applyAppearance('dark');
    applyAppearance('system');
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
  });

  it('keeps the choice for this page when storage is blocked', () => {
    blockStorage();
    expect(loadAppearance()).toBe('system');
    expect(() => storeAppearance('dark')).not.toThrow();
    expect(getAppearance()).toBe('dark');
    expect(theme()).toBe('dark');
    expect(() => storeAppearance('system')).not.toThrow();
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });

  it('tells its subscribers about a change', () => {
    const listener = vi.fn();
    const unsubscribe = subscribeAppearance(listener);
    storeAppearance('dark');
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
    storeAppearance('light');
    expect(listener).toHaveBeenCalledTimes(1);
  });
});

describe('starting', () => {
  it('applies the stored choice again', () => {
    stop();
    localStorage.setItem('rola.appearance', 'light');
    stop = startAppearance();
    expect(theme()).toBe('light');
    expect(getAppearance()).toBe('light');
  });

  it('removes an attribute that storage no longer backs', () => {
    stop();
    document.documentElement.dataset.theme = 'dark';
    stop = startAppearance();
    expect(theme()).toBeNull();
    expect(getAppearance()).toBe('system');
  });
});

describe('another tab', () => {
  it('passes its choice to this page', () => {
    const listener = vi.fn();
    subscribeAppearance(listener);
    otherTab('rola.appearance', 'dark');
    expect(getAppearance()).toBe('dark');
    expect(theme()).toBe('dark');
    expect(listener).toHaveBeenCalled();
    otherTab('rola.appearance', null);
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });

  it('leaves no choice when it clears the storage', () => {
    storeAppearance('dark');
    otherTab(null, null);
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });

  it('is ignored for other keys and unknown values', () => {
    storeAppearance('light');
    otherTab('token', 'dark');
    otherTab('rola.appearance', 'sepia');
    expect(getAppearance()).toBe('light');
    expect(theme()).toBe('light');
  });

  it('is ignored for session storage', () => {
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: 'rola.appearance',
        newValue: 'dark',
        storageArea: sessionStorage,
      }),
    );
    expect(getAppearance()).toBe('system');
  });

  it('is no longer followed once stopped', () => {
    stop();
    otherTab('rola.appearance', 'dark');
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });
});

describe('a page restored from the back/forward cache', () => {
  // Another tab stored the choice while this page was frozen, so no storage
  // event reached it.
  function shown(persisted: boolean) {
    localStorage.setItem('rola.appearance', 'dark');
    window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted }));
  }

  it('reads the stored choice again', () => {
    const listener = vi.fn();
    subscribeAppearance(listener);
    shown(true);
    expect(getAppearance()).toBe('dark');
    expect(theme()).toBe('dark');
    expect(listener).toHaveBeenCalled();
  });

  it('is not read again for a page that was not restored', () => {
    shown(false);
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });

  it('is no longer followed once stopped', () => {
    stop();
    shown(true);
    expect(getAppearance()).toBe('system');
    expect(theme()).toBeNull();
  });
});
