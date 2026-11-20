import { expect, it } from 'vitest';
import { apiDate } from './upload';

it('writes the date of birth as the API takes it, with leading zeros', () => {
  expect(apiDate(new Date(2010, 2, 7))).toBe('2010-03-07');
  expect(apiDate(new Date(1998, 11, 24))).toBe('1998-12-24');
});

it('keeps the calendar day of a date late in the evening', () => {
  // Late in the evening a UTC-based format moves the date a day on west of
  // Greenwich; the local calendar fields do not.
  expect(apiDate(new Date(2010, 0, 1, 23, 30))).toBe('2010-01-01');
});
