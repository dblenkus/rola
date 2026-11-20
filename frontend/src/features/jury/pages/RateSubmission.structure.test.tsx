import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import {
  contestWithTheme,
  jurySubmission,
  rating,
} from '../../../test/fixtures';
import {
  announcement,
  exactText,
  photoScore,
  pressedScore,
  renderRater,
  scoreGroup,
  scoreKey,
  scores,
  serveJudging,
  settle,
} from './RateSubmission.testutils';

let store: AppStore;

beforeEach(() => {
  localStorage.clear();
  store = createAppStore();
});

const twoSubmissions = [
  jurySubmission(11, 'First'),
  jurySubmission(12, 'Second'),
];

it('shows the photograph with its id, position and title', async () => {
  serveJudging({ submissions: twoSubmissions });
  renderRater(store);

  const photo = await screen.findByRole('img', { name: 'First' });
  expect(photo).toHaveAttribute('src', 'https://media.example/11.jpg');
  const label = photoScore();
  expect(within(label).getByText(exactText('#0011'))).toBeVisible();
  expect(within(label).getByText(exactText('1 / 2'))).toBeVisible();
  expect(
    within(label).getByRole('heading', { level: 1, name: 'First' }),
  ).toBeVisible();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
});

it('shows the position of the photograph after moving on', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  const label = photoScore();
  expect(within(label).getByText(exactText('#0012'))).toBeVisible();
  expect(within(label).getByText(exactText('2 / 2'))).toBeVisible();
  expect(
    within(label).getByRole('heading', { level: 1, name: 'Second' }),
  ).toBeVisible();
});

// A browser paints an image's old picture until its new source has loaded,
// so the next photograph gets an image element of its own.
it('shows the next photograph in a new image element', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  const first = await screen.findByRole('img', { name: 'First' });

  await user.click(screen.getByRole('button', { name: 'Next' }));
  const second = await screen.findByRole('img', { name: 'Second' });
  expect(second).not.toBe(first);
  expect(first).not.toBeInTheDocument();
});

it('shows the description of a submission that has one', async () => {
  serveJudging({
    submissions: [
      { ...jurySubmission(11, 'First'), description: 'Fog over the valley.' },
    ],
  });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  expect(
    within(photoScore()).getByText(exactText('Fog over the valley.')),
  ).toBeVisible();
});

it('titles a submission without a title "Untitled"', async () => {
  serveJudging({ submissions: [{ ...jurySubmission(11, ''), title: null }] });
  renderRater(store);

  expect(
    await within(
      await screen.findByRole('region', { name: 'Photo score' }),
    ).findByRole('heading', { level: 1, name: 'Untitled' }),
  ).toBeVisible();
});

it('shows every photograph of a series with its place in the series', async () => {
  const consoleError = vi.spyOn(console, 'error');
  const files = [21, 22, 23, 24].flatMap((id) => jurySubmission(id, '').files);
  serveJudging({
    contest: contestWithTheme({ is_series: true, n_photos: 4 }),
    submissions: [{ ...jurySubmission(11, 'Bridges'), files }],
  });
  renderRater(store);

  await screen.findAllByRole('img', { name: 'Bridges' });
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
  for (const caption of ['1 / 4', '2 / 4', '3 / 4', '4 / 4']) {
    expect(screen.getByText(exactText(caption))).toBeVisible();
  }
  expect(
    consoleError.mock.calls.filter(([message]) =>
      String(message).includes('unique "key"'),
    ),
  ).toEqual([]);
});

it('shows a series of more than six photographs in full', async () => {
  const ids = [21, 22, 23, 24, 25, 26, 27, 28];
  const files = ids.flatMap((id) => jurySubmission(id, '').files);
  serveJudging({
    contest: contestWithTheme({ is_series: true, n_photos: 8 }),
    submissions: [{ ...jurySubmission(11, 'Bridges'), files }],
  });
  renderRater(store);

  await screen.findAllByRole('img', { name: 'Bridges' });
  expect(
    screen
      .getAllByRole('img', { name: 'Bridges' })
      .map((image) => image.getAttribute('src')),
  ).toEqual(ids.map((id) => `https://media.example/${id}.jpg`));
});

it('names the ten score keys with their keyboard shortcuts', async () => {
  serveJudging({ submissions: twoSubmissions });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  expect(within(scoreGroup()).getAllByRole('button')).toHaveLength(10);
  for (const value of scores) {
    const key = scoreKey(value);
    expect(key).toHaveAttribute('aria-keyshortcuts', String(value % 10));
    expect(key).toHaveAttribute('aria-pressed', 'false');
  }
});

it('presses only the key of the loaded score', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 8)],
  });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await waitFor(() =>
    expect(scoreKey(8)).toHaveAttribute('aria-pressed', 'true'),
  );
  for (const value of scores.filter((value) => value !== 8)) {
    expect(scoreKey(value)).toHaveAttribute('aria-pressed', 'false');
  }
});

it('names the clear, navigation and shortcut controls with their keys', async () => {
  serveJudging({ submissions: twoSubmissions });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  expect(screen.getByRole('button', { name: 'Clear' })).toHaveAttribute(
    'aria-keyshortcuts',
    'Backspace',
  );
  expect(screen.getByRole('button', { name: 'Previous' })).toHaveAttribute(
    'aria-keyshortcuts',
    'ArrowLeft',
  );
  expect(screen.getByRole('button', { name: 'Next' })).toHaveAttribute(
    'aria-keyshortcuts',
    'ArrowRight',
  );
  expect(
    screen.getByRole('button', { name: 'Keyboard shortcuts' }),
  ).toHaveAttribute('aria-pressed', 'true');
});

it('disables Clear while the photograph has no score', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();
  expect(screen.getByRole('button', { name: 'Clear' })).toHaveAttribute(
    'aria-disabled',
    'true',
  );

  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));
  expect(screen.getByRole('button', { name: 'Clear' })).not.toHaveAttribute(
    'aria-disabled',
    'true',
  );
});

it('does nothing when Previous is pressed on the first photograph', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  const router = renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  const previous = screen.getByRole('button', { name: 'Previous' });
  expect(previous).toHaveAttribute('aria-disabled', 'true');
  expect(screen.getByRole('button', { name: 'Next' })).not.toHaveAttribute(
    'aria-disabled',
    'true',
  );
  await user.click(previous);
  await settle();
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  expect(router.state.location.search).toBe('?submission=11');
});

it('does nothing when Next is pressed on the last photograph', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  const router = renderRater(store, {
    path: '/judge/contest/1/theme/2/rate?submission=12',
  });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();

  const next = screen.getByRole('button', { name: 'Next' });
  expect(next).toHaveAttribute('aria-disabled', 'true');
  expect(screen.getByRole('button', { name: 'Previous' })).not.toHaveAttribute(
    'aria-disabled',
    'true',
  );
  await user.click(next);
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(router.state.location.search).toBe('?submission=12');
});

it('links back to the theme', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  const router = renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  const back = screen.getByRole('link', { name: 'Back to theme' });
  expect(back).toHaveAttribute('href', '/judge/contest/1/theme/2');
  await user.click(back);
  expect(await screen.findByText('Theme overview')).toBeVisible();
  expect(router.state.location.pathname).toBe('/judge/contest/1/theme/2');
});

it('titles the document with the theme', async () => {
  serveJudging({ submissions: twoSubmissions });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await waitFor(() => expect(document.title).toBe('Nature · Rola'));
});

it('announces nothing before the judge acts', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 8)],
  });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(8));

  expect(announcement()).toBe('');
});
