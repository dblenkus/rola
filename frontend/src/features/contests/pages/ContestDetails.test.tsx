import { getDefaultNormalizer, render, screen } from '@testing-library/react';
import i18next from 'i18next';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { serveApi } from '../../../test/api';
import { contest } from '../../../test/fixtures';
import ContestDetails from './ContestDetails';

function openDetails(overrides: Partial<typeof contest> = {}) {
  serveApi({ 'GET /contest/1': () => ({ ...contest, ...overrides }) });
  return render(
    <MemoryRouter initialEntries={['/contest/1/details']}>
      <Routes>
        <Route
          path="/contest/:contestId/details"
          element={<ContestDetails />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

// Matches the text as rendered, so the dates' no-break spaces count.
const exact = {
  normalizer: getDefaultNormalizer({ collapseWhitespace: false }),
};

describe('contest details', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(2026, 10, 15, 12, 0));
  });

  afterEach(async () => {
    vi.useRealTimers();
    await i18next.changeLanguage('en');
  });

  it('titles the page with the contest', async () => {
    openDetails({ end_date: '2026-12-07' });
    const title = await screen.findByRole('heading', {
      level: 1,
      name: contest.title,
    });
    expect(title).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(document.title).toBe(`${contest.title} · Rola`);
  });

  it('gives the closing date and the days left under the title', async () => {
    openDetails({ end_date: '2026-12-07' });
    const date = await screen.findByText('7\u00a0Dec\u00a02026', exact);
    expect(date.tagName).toBe('STRONG');
    expect(date.parentElement?.textContent).toBe(
      'Entries close 7\u00a0Dec\u00a02026 · 22 days left',
    );
  });

  it('writes the deadline line natively in Slovenian', async () => {
    await i18next.changeLanguage('sl');
    openDetails({ end_date: '2026-11-17' });
    const date = await screen.findByText('17.\u00a011.\u00a02026', exact);
    expect(date.parentElement?.textContent).toBe(
      'Prijave do 17.\u00a011.\u00a02026 · še 2 dneva',
    );
  });

  it('shows the header image whole, with an empty alt', async () => {
    openDetails({ header_image: 'https://media.example/header.jpg' });
    await screen.findByRole('heading', { level: 1, name: contest.title });
    const image = document.querySelector(
      'img[src="https://media.example/header.jpg"]',
    );
    expect(image).toHaveAttribute('alt', '');
    expect(image).toHaveAttribute('loading', 'eager');
    expect(image).toHaveAttribute('decoding', 'async');
  });

  it('shows no image when the contest has none', async () => {
    openDetails();
    await screen.findByRole('heading', { level: 1, name: contest.title });
    expect(document.querySelector('img')).toBeNull();
  });

  it('links to the upload twice, with one primary action', async () => {
    const { container } = openDetails();
    await screen.findByText('Contest instructions');
    const uploads = screen.getAllByRole('link', { name: 'Upload Photos' });
    expect(uploads).toHaveLength(2);
    for (const upload of uploads) {
      expect(upload).toHaveAttribute('href', '/contest/1/upload');
    }
    expect(uploads[0]).toHaveClass('rl-btn--primary');
    expect(uploads[1]).toHaveClass('rl-btn--secondary');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(container.querySelector('[class*="Mui"]')).toBeNull();
  });
});
