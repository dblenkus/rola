import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { expect, it, vi } from 'vitest';
import '../../../app/i18n/config';
import { jurySubmission } from '../../../test/fixtures';
import type { JurySubmission, Rating } from '../../../shared/api/types';
import ThemeGallery from './ThemeGallery';

function rating(submission: number, value: number): Rating {
  return {
    id: submission * 10,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    submission,
    rating: value,
  };
}

const raterLink = (id: number) => `/rate?submission=${id}`;

function renderGallery(
  submissions: JurySubmission[],
  ratings: Rating[],
  onOpen = vi.fn(),
) {
  render(
    <MemoryRouter initialEntries={['/gallery']}>
      <Routes>
        <Route
          path="/gallery"
          element={
            <ThemeGallery
              submissions={submissions}
              ratings={ratings}
              raterLink={raterLink}
              onOpen={onOpen}
            />
          }
        />
        <Route path="/rate" element={<p>Rater</p>} />
      </Routes>
    </MemoryRouter>,
  );
  return onOpen;
}

function cell(name: string): HTMLElement {
  const link = screen
    .getAllByRole('link')
    .find((candidate) => within(candidate).queryByRole('img', { name }));
  if (!link) {
    throw new Error(`No gallery cell for ${name}`);
  }
  return link;
}

it('links each photograph to the rater with its ID and lazy thumbnail', () => {
  const withThumbnail: JurySubmission = {
    ...jurySubmission(12, 'Second'),
    files: jurySubmission(12, 'Second').files.map((file) => ({
      ...file,
      thumbnail: 'https://media.example/12-small.jpg',
    })),
  };
  renderGallery([jurySubmission(11, 'First'), withThumbnail], []);

  const first = cell('First');
  expect(first).toHaveAttribute('href', '/rate?submission=11');
  expect(within(first).getByText('#0011')).toBeVisible();
  const firstImage = within(first).getByRole('img', { name: 'First' });
  expect(firstImage).toHaveAttribute('src', 'https://media.example/11.jpg');
  expect(firstImage).toHaveAttribute('loading', 'lazy');

  const second = cell('Second');
  expect(second).toHaveAttribute('href', '/rate?submission=12');
  expect(within(second).getByText('#0012')).toBeVisible();
  expect(within(second).getByRole('img', { name: 'Second' })).toHaveAttribute(
    'src',
    'https://media.example/12-small.jpg',
  );
});

it("shows the judge's score as a figure and a dash for an unscored photograph", () => {
  renderGallery(
    [jurySubmission(11, 'First'), jurySubmission(12, 'Second')],
    [rating(11, 8)],
  );

  const scored = cell('First');
  expect(within(scored).getByText('8')).toBeVisible();
  expect(within(scored).getByText('Score 8')).toBeInTheDocument();
  expect(within(scored).queryByText('–')).not.toBeInTheDocument();

  const unscored = cell('Second');
  expect(within(unscored).getByText('–')).toBeVisible();
  expect(within(unscored).getByText('Unscored')).toBeInTheDocument();
});

it('shows the first photograph of a series and how many it has', () => {
  const series: JurySubmission = {
    ...jurySubmission(11, 'Bridges'),
    files: [21, 22, 23, 24].flatMap((id) => jurySubmission(id, '').files),
  };
  renderGallery([series], []);

  const images = screen.getAllByRole('img', { name: 'Bridges' });
  expect(images.map((image) => image.getAttribute('src'))).toEqual([
    'https://media.example/21.jpg',
  ]);
  const link = cell('Bridges');
  expect(within(link).getByText('1 / 4')).toBeVisible();
  expect(within(link).getByText('First of 4 photos')).toBeInTheDocument();
});

it('shows no photograph count for a single photograph', () => {
  renderGallery([jurySubmission(11, 'First')], []);

  expect(within(cell('First')).queryByText(/ \/ /)).not.toBeInTheDocument();
});

it('reports the submission it opens before the rater shows', async () => {
  const onOpen = renderGallery([jurySubmission(11, 'First')], []);

  await userEvent.setup().click(screen.getByRole('img', { name: 'First' }));

  expect(onOpen).toHaveBeenCalledWith(11);
  expect(await screen.findByText('Rater')).toBeVisible();
});
