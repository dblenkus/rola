import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { loadShortcutsOn, storeShortcutsOn } from './shortcutsSetting';

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

it('has the shortcuts on until they are turned off', () => {
  expect(loadShortcutsOn()).toBe(true);
  storeShortcutsOn(false);
  expect(localStorage.getItem('rola.judge.shortcuts')).toBe('off');
  expect(loadShortcutsOn()).toBe(false);
  storeShortcutsOn(true);
  expect(localStorage.getItem('rola.judge.shortcuts')).toBeNull();
  expect(loadShortcutsOn()).toBe(true);
});

it('reads an unknown stored value as on', () => {
  localStorage.setItem('rola.judge.shortcuts', 'on');
  expect(loadShortcutsOn()).toBe(true);
});

it('has the shortcuts on and keeps working when storage is blocked', () => {
  const blocked = () => {
    throw new DOMException('Blocked', 'SecurityError');
  };
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(blocked);
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(blocked);
  vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(blocked);

  expect(loadShortcutsOn()).toBe(true);
  expect(() => storeShortcutsOn(false)).not.toThrow();
  expect(() => storeShortcutsOn(true)).not.toThrow();
});
