import { expect, it } from 'vitest';
import photoId from './photoId';

it('pads an id to four digits after "#"', () => {
  expect(photoId(7)).toBe('#0007');
  expect(photoId(275)).toBe('#0275');
  expect(photoId(12345)).toBe('#12345');
});

it('refuses an id that is not a whole number from 0', () => {
  expect(() => photoId(-1)).toThrow('Invalid submission id: -1');
  expect(() => photoId(1.5)).toThrow('Invalid submission id: 1.5');
});
