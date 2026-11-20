import {
  getDefaultNormalizer,
  render,
  screen,
  within,
} from '@testing-library/react';
import i18next from 'i18next';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../app/i18n/config';
import { apiDateTime, contest } from '../../../test/fixtures';
import ContestRow from './ContestRow';

describe('contest information', () => {
  it('shows the contest and opens its upload route', () => {
    render(
      <MemoryRouter>
        <ContestRow contest={contest} />
      </MemoryRouter>,
    );
    expect(
      screen.getByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    expect(screen.getByText(contest.description ?? '')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /open/i })).toHaveAttribute(
      'href',
      '/contest/1/upload',
    );
    expect(screen.getByText('31 Dec 2026')).toBeInTheDocument();
  });
});

// Matches the text as rendered, so the dates' no-break spaces count.
const exact = {
  normalizer: getDefaultNormalizer({ collapseWhitespace: false }),
};

describe('contest row', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(2026, 10, 15, 12, 0));
  });

  afterEach(async () => {
    vi.useRealTimers();
    await i18next.changeLanguage('en');
  });

  function renderRow(endDate: string) {
    return render(
      <MemoryRouter>
        <ul>
          <ContestRow contest={{ ...contest, end_date: endDate }} />
        </ul>
      </MemoryRouter>,
    );
  }

  it('names the contest in a second-level heading linking to its details', () => {
    renderRow('2026-12-07');
    const heading = screen.getByRole('heading', {
      level: 2,
      name: contest.title,
    });
    expect(within(heading).getByRole('link')).toHaveAttribute(
      'href',
      '/contest/1/details',
    );
  });

  it('gives the closing date and the days left in English', () => {
    renderRow('2026-12-07');
    expect(screen.getByText('Entries close')).toBeInTheDocument();
    expect(screen.getByText('7\u00a0Dec\u00a02026', exact)).toBeInTheDocument();
    expect(screen.getByText('(22 days left)')).toBeInTheDocument();
  });

  it.each([
    ['2026-12-07', '(še 22 dni)'],
    ['2026-11-17', '(še 2 dneva)'],
    ['2026-11-18', '(še 3 dnevi)'],
    ['2026-11-16', '(še 1 dan)'],
  ])(
    'gives the closing date %s and the days left in Slovenian',
    async (endDate, note) => {
      await i18next.changeLanguage('sl');
      renderRow(endDate);
      expect(screen.getByText('Prijave do')).toBeInTheDocument();
      expect(screen.getByText(note)).toBeInTheDocument();
    },
  );

  it('writes the date the Slovenian way', async () => {
    await i18next.changeLanguage('sl');
    renderRow('2026-12-07');
    expect(
      screen.getByText('7.\u00a012.\u00a02026', exact),
    ).toBeInTheDocument();
  });

  it('says that the closing day has come', () => {
    renderRow(new Date(2026, 10, 15, 20, 0).toISOString());
    expect(screen.getByText('(last day)')).toBeInTheDocument();
  });

  it('says that entries have closed, without days left', () => {
    renderRow(new Date(2026, 10, 15, 11, 0).toISOString());
    expect(screen.getByText('Entries closed')).toBeInTheDocument();
    expect(
      screen.getByText('15\u00a0Nov\u00a02026', exact),
    ).toBeInTheDocument();
    expect(screen.queryByText(/left|last day/)).not.toBeInTheDocument();
  });

  // The API sends the closing moment as a date-time; just before and just
  // after local midnight it names the local calendar day, whatever day the
  // instant falls on in UTC.
  it.each([
    [
      'offset',
      'before midnight',
      new Date(2026, 11, 7, 23, 59, 59),
      '7\u00a0Dec\u00a02026',
      22,
    ],
    [
      'utc',
      'before midnight',
      new Date(2026, 11, 7, 23, 59, 59),
      '7\u00a0Dec\u00a02026',
      22,
    ],
    [
      'offset',
      'after midnight',
      new Date(2026, 11, 8, 0, 0, 30),
      '8\u00a0Dec\u00a02026',
      23,
    ],
    [
      'utc',
      'after midnight',
      new Date(2026, 11, 8, 0, 0, 30),
      '8\u00a0Dec\u00a02026',
      23,
    ],
  ] as const)(
    'gives a closing date-time in %s time %s as its local day',
    (form, _when, end, date, days) => {
      renderRow(apiDateTime(end, form));
      expect(screen.getByText(date, exact)).toBeInTheDocument();
      expect(screen.getByText(`(${days} days left)`)).toBeInTheDocument();
    },
  );

  it('opens the upload as a secondary link-button', () => {
    renderRow('2026-12-07');
    expect(screen.getByRole('link', { name: 'Open' })).toHaveClass(
      'rl-btn',
      'rl-btn--secondary',
    );
  });
});
