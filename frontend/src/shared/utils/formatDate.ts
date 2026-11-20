export type DateLanguage = 'sl' | 'en';

// U+00A0, so a date never breaks across lines.
const NBSP = '\u00a0';

// en-US gives the three-letter "Sep"; en-GB has "Sept".
const englishMonth = new Intl.DateTimeFormat('en-US', { month: 'short' });

const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/;
const dateTime =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

// Reads a date from the API. Contest dates are Django DateTimeFields, which
// the API sends as ISO 8601 date-times with an offset ("2026-11-15T22:59:59Z"):
// an instant, shown on the calendar of the browser's time zone. A date-only
// value ("2026-11-15") names a calendar day, so it is read as local midnight;
// `new Date('2026-11-15')` would read it as UTC midnight and show the day
// before west of Greenwich. Anything else is a contract error.
export function parseApiDate(value: string): Date {
  const day = dateOnly.exec(value);
  if (day) {
    return new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]));
  }
  if (dateTime.test(value)) {
    return new Date(value);
  }
  throw new Error(`Not an ISO 8601 date or date-time with offset: ${value}`);
}

// The date as Rola writes it, in the browser's time zone: "15. 11. 2026" in
// Slovenian (no leading zeros), "15 Nov 2026" in English (no comma).
export function formatDate(date: Date, language: DateLanguage): string {
  const day = date.getDate();
  const year = date.getFullYear();
  if (language === 'sl') {
    return [`${day}.`, `${date.getMonth() + 1}.`, year].join(NBSP);
  }
  return [day, englishMonth.format(date), year].join(NBSP);
}

// Whole calendar days from `now` to `date` in the browser's time zone: 0 on
// the day itself, negative after it. Counting calendar dates rather than
// 24-hour spans keeps daylight-saving days from shifting the count.
export function daysLeft(date: Date, now: Date): number {
  const calendarDay = (value: Date) =>
    Date.UTC(value.getFullYear(), value.getMonth(), value.getDate());
  return Math.round((calendarDay(date) - calendarDay(now)) / 86_400_000);
}
