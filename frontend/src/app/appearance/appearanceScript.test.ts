import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// The script that index.html links before the app, as the browser gets it.
import script from '../../../public/appearance.js?raw';
import { type Appearance, storeAppearance } from './appearanceSetting';

const theme = () => document.documentElement.getAttribute('data-theme');

// Runs the script as a classic script would, against this document.
const run = () => new Function(script)();

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

describe('public/appearance.js', () => {
  it.each<[Appearance, string | null]>([
    ['light', 'light'],
    ['dark', 'dark'],
    ['system', null],
  ])('applies %s as the app stores it', (choice, attribute) => {
    // The app writes the choice, so the test fails if the two disagree on
    // the key or the values.
    storeAppearance(choice);
    document.documentElement.removeAttribute('data-theme');
    run();
    expect(theme()).toBe(attribute);
  });

  it.each(['system', 'Dark', 'sepia', ''])(
    'leaves the page to the device for the stored value %j',
    (value) => {
      localStorage.setItem('rola.appearance', value);
      run();
      expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    },
  );

  describe('with blocked storage', () => {
    const own = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');

    beforeEach(() => {
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        get() {
          throw new DOMException('Blocked', 'SecurityError');
        },
      });
    });

    afterEach(() => {
      if (own === undefined) {
        Reflect.deleteProperty(globalThis, 'localStorage');
      } else {
        Object.defineProperty(globalThis, 'localStorage', own);
      }
    });

    it('does not throw and leaves the page to the device', () => {
      expect(run).not.toThrow();
      expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    });
  });
});
