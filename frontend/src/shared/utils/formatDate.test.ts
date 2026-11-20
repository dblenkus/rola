import i18next from 'i18next';
import { describe, expect, it } from 'vitest';
import {
  daysLeft,
  formatDate,
  formatDateTime,
  parseApiDate,
} from './formatDate';

describe('formatDate', () => {
  it('writes a Slovenian date without leading zeros', () => {
    expect(formatDate(new Date(2026, 10, 15), 'sl')).toBe(
      '15.\u00a011.\u00a02026',
    );
    expect(formatDate(new Date(2027, 1, 1), 'sl')).toBe('1.\u00a02.\u00a02027');
  });

  it('writes an English date with the three-letter month and no comma', () => {
    expect(formatDate(new Date(2026, 10, 15), 'en')).toBe(
      '15\u00a0Nov\u00a02026',
    );
    expect(formatDate(new Date(2027, 1, 1), 'en')).toBe('1\u00a0Feb\u00a02027');
    expect(formatDate(new Date(2026, 8, 3), 'en')).toBe('3\u00a0Sep\u00a02026');
  });

  it('separates the parts with no-break spaces only', () => {
    for (const language of ['sl', 'en'] as const) {
      const text = formatDate(new Date(2026, 10, 15), language);
      expect(text).not.toMatch(/ /);
      expect(text.split('\u00a0')).toHaveLength(3);
    }
  });
});

describe('formatDateTime', () => {
  it('writes the date and the 24-hour time in Slovenian', () => {
    expect(formatDateTime(new Date(2026, 10, 20, 18, 18, 21), 'sl')).toBe(
      '20.\u00a011.\u00a02026,\u00a018:18',
    );
  });

  it('writes the date and the 24-hour time in English', () => {
    expect(formatDateTime(new Date(2026, 10, 20, 18, 18, 21), 'en')).toBe(
      '20\u00a0Nov\u00a02026,\u00a018:18',
    );
  });

  it('writes the hour without a leading zero and the minutes with one', () => {
    expect(formatDateTime(new Date(2026, 0, 5, 7, 4), 'sl')).toBe(
      '5.\u00a01.\u00a02026,\u00a07:04',
    );
    expect(formatDateTime(new Date(2026, 0, 5, 0, 0), 'en')).toBe(
      '5\u00a0Jan\u00a02026,\u00a00:00',
    );
  });
});

describe('parseApiDate', () => {
  it('reads a date-only value as that day in the local time zone', () => {
    const date = parseApiDate('2026-01-05');
    expect([date.getFullYear(), date.getMonth(), date.getDate()]).toEqual([
      2026, 0, 5,
    ]);
    expect([date.getHours(), date.getMinutes()]).toEqual([0, 0]);
  });

  it('reads a date-time with an offset as that instant', () => {
    expect(parseApiDate('2026-11-15T12:00:00Z').getTime()).toBe(
      Date.UTC(2026, 10, 15, 12),
    );
    expect(parseApiDate('2026-11-15T12:00:00.5+01:00').getTime()).toBe(
      Date.UTC(2026, 10, 15, 11, 0, 0, 500),
    );
  });

  it('refuses a value it cannot place in time', () => {
    expect(() => parseApiDate('2026-11-15T12:00:00')).toThrow();
    expect(() => parseApiDate('15. 11. 2026')).toThrow();
    expect(() => parseApiDate('')).toThrow();
  });
});

describe('daysLeft', () => {
  const now = new Date(2026, 10, 15, 12, 0);

  it('is 0 on the day itself, whatever the hour', () => {
    expect(daysLeft(new Date(2026, 10, 15, 0, 0), now)).toBe(0);
    expect(daysLeft(new Date(2026, 10, 15, 23, 59), now)).toBe(0);
  });

  it('counts calendar days across the day boundary', () => {
    expect(daysLeft(new Date(2026, 10, 16, 0, 0), now)).toBe(1);
    expect(
      daysLeft(new Date(2026, 10, 16, 0, 1), new Date(2026, 10, 15, 23, 59)),
    ).toBe(1);
    expect(daysLeft(new Date(2026, 11, 7), now)).toBe(22);
  });

  it('counts across a daylight-saving change and into the next year', () => {
    expect(daysLeft(new Date(2027, 2, 30), new Date(2027, 2, 27))).toBe(3);
    expect(daysLeft(new Date(2027, 0, 1), new Date(2026, 11, 31, 23))).toBe(1);
  });

  it('is negative after the day', () => {
    expect(daysLeft(new Date(2026, 10, 14, 23, 59), now)).toBe(-1);
  });
});

describe('days left wording', () => {
  it.each([
    [1, 'še 1 dan'],
    [2, 'še 2 dneva'],
    [3, 'še 3 dnevi'],
    [5, 'še 5 dni'],
    [101, 'še 101 dan'],
  ])('uses the Slovenian plural form for %i', (count, text) => {
    expect(i18next.t('date_days_left', { count, lng: 'sl' })).toBe(text);
  });

  it.each([
    [1, '1 day left'],
    [2, '2 days left'],
    [22, '22 days left'],
  ])('uses the English plural form for %i', (count, text) => {
    expect(i18next.t('date_days_left', { count, lng: 'en' })).toBe(text);
  });
});
