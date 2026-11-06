import { render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import '../../i18n/config';
import { jurySubmission } from '../../test/fixtures';
import SubmissionRater from './SubmissionRater';

afterEach(() => {
  vi.restoreAllMocks();
});

it('shows every photograph of a series without React key warnings', () => {
  const consoleError = vi.spyOn(console, 'error');
  const files = [21, 22, 23, 24].flatMap((id) => jurySubmission(id, '').files);

  render(
    <SubmissionRater
      submission={{ ...jurySubmission(11, 'Bridges'), files }}
      rating={0}
      isSeries
      isPrevious={false}
      isNext={false}
      close={vi.fn()}
      previousSubmission={vi.fn()}
      nextSubmission={vi.fn()}
      updateRating={vi.fn()}
    />,
  );

  expect(
    screen
      .getAllByRole('img', { name: 'Bridges' })
      .map((image) => image.getAttribute('src')),
  ).toEqual([
    'https://media.example/21.jpg',
    'https://media.example/22.jpg',
    'https://media.example/23.jpg',
    'https://media.example/24.jpg',
  ]);
  expect(
    consoleError.mock.calls.filter(([message]) =>
      String(message).includes('unique "key"'),
    ),
  ).toEqual([]);
});
