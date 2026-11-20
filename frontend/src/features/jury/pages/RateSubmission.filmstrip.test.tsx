import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import { jurySubmission, rating } from '../../../test/fixtures';
import {
  announcement,
  exactText,
  pressedScore,
  renderRater,
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

// Submissions 101 to 160: frame n shows submission 100 + n.
const sixtySubmissions = Array.from({ length: 60 }, (_, index) =>
  jurySubmission(101 + index, `Photo ${index + 1}`),
);

const rateAt = (submissionId: number) =>
  `/judge/contest/1/theme/2/rate?submission=${submissionId}`;

const filmstrip = (first: number, last: number, total: number) =>
  screen.getByRole('navigation', {
    name: `Photo sequence, frames ${first} to ${last} of ${total}`,
  });

it('counts the photographs the judge has scored in the theme', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});

it('counts a score given and a score cleared', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();

  await user.keyboard('8');
  expect(await screen.findByText(exactText('Scored 2 / 2'))).toBeVisible();
  await user.keyboard('{Backspace}');
  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();
});

it('keeps the count when a scored photograph is scored again', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store, { path: rateAt(12) });
  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  await settle();
  expect(screen.getByText(exactText('Scored 1 / 2'))).toBeVisible();
});

it('names the frames by their number and score', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  const strip = await screen.findByRole('navigation', {
    name: 'Photo sequence, frames 1 to 2 of 2',
  });
  expect(within(strip).getAllByRole('link')).toHaveLength(2);
  expect(
    await within(strip).findByRole('link', { name: 'Frame 2, score 4' }),
  ).not.toHaveAttribute('aria-current', 'true');
  expect(
    within(strip).getByRole('link', { name: 'Frame 1, unscored' }),
  ).toHaveAttribute('aria-current', 'true');
  // The link names the frame, so its image has no name of its own.
  expect(within(strip).queryAllByRole('img')).toEqual([]);
});

it('renames the frame of a photograph when it is scored or cleared', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(
    await screen.findByRole('link', { name: 'Frame 1, unscored' }),
  ).toBeVisible();

  await user.keyboard('8');
  expect(
    await screen.findByRole('link', { name: 'Frame 1, score 8' }),
  ).toBeVisible();
  await user.keyboard('{Backspace}');
  expect(
    await screen.findByRole('link', { name: 'Frame 1, unscored' }),
  ).toBeVisible();
});

it('shows the photograph of an activated frame', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  const router = renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.click(
    await screen.findByRole('link', { name: 'Frame 2, score 4' }),
  );
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));
  expect(
    screen.getByRole('link', { name: 'Frame 2, score 4' }),
  ).toHaveAttribute('aria-current', 'true');
  expect(
    screen.getByRole('link', { name: 'Frame 1, unscored' }),
  ).not.toHaveAttribute('aria-current', 'true');
  expect(router.state.location.search).toBe('?submission=12');
});

it('shows at most twenty frames on either side of the current one', async () => {
  serveJudging({ submissions: sixtySubmissions });
  renderRater(store, { path: rateAt(130) });
  expect(await screen.findByRole('img', { name: 'Photo 30' })).toBeVisible();
  await screen.findByRole('link', { name: 'Frame 30, unscored' });

  const strip = filmstrip(10, 50, 60);
  expect(within(strip).getAllByRole('link')).toHaveLength(41);
  expect(
    within(strip).getByRole('link', { name: 'Frame 10, unscored' }),
  ).toBeVisible();
  expect(
    within(strip).getByRole('link', { name: 'Frame 50, unscored' }),
  ).toBeVisible();
  expect(
    within(strip).getByRole('link', { name: 'Frame 30, unscored' }),
  ).toHaveAttribute('aria-current', 'true');
  expect(
    within(strip).queryByRole('link', { name: /^Frame (9|51),/ }),
  ).not.toBeInTheDocument();
});

it('moves the frames with the current photograph', async () => {
  serveJudging({ submissions: sixtySubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: rateAt(130) });
  expect(await screen.findByRole('img', { name: 'Photo 30' })).toBeVisible();

  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(await screen.findByRole('img', { name: 'Photo 31' })).toBeVisible();
  const strip = filmstrip(11, 51, 60);
  expect(within(strip).getAllByRole('link')).toHaveLength(41);
  expect(
    within(strip).getByRole('link', { name: 'Frame 31, unscored' }),
  ).toHaveAttribute('aria-current', 'true');
});

it('moves focus to the current frame when the focused frame leaves the strip', async () => {
  serveJudging({ submissions: sixtySubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: rateAt(130) });
  expect(await screen.findByRole('img', { name: 'Photo 30' })).toBeVisible();
  const edge = await screen.findByRole('link', { name: 'Frame 10, unscored' });
  act(() => edge.focus());

  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Photo 31' })).toBeVisible();
  expect(edge).not.toBeInTheDocument();
  expect(
    within(filmstrip(11, 51, 60)).getByRole('link', {
      name: 'Frame 31, unscored',
    }),
  ).toHaveFocus();
});

it('keeps focus on a focused frame that stays in the strip', async () => {
  serveJudging({ submissions: sixtySubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: rateAt(130) });
  expect(await screen.findByRole('img', { name: 'Photo 30' })).toBeVisible();
  const inside = await screen.findByRole('link', {
    name: 'Frame 12, unscored',
  });
  act(() => inside.focus());

  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Photo 31' })).toBeVisible();
  await settle();
  expect(inside).toHaveFocus();
});

it('shows fewer frames near the first photograph', async () => {
  serveJudging({ submissions: sixtySubmissions });
  renderRater(store, { path: rateAt(101) });
  expect(await screen.findByRole('img', { name: 'Photo 1' })).toBeVisible();
  await screen.findByRole('link', { name: 'Frame 1, unscored' });
  expect(within(filmstrip(1, 21, 60)).getAllByRole('link')).toHaveLength(21);
});

it('shows fewer frames near the last photograph', async () => {
  serveJudging({ submissions: sixtySubmissions });
  renderRater(store, { path: rateAt(160) });
  expect(await screen.findByRole('img', { name: 'Photo 60' })).toBeVisible();
  await screen.findByRole('link', { name: 'Frame 60, unscored' });
  expect(within(filmstrip(40, 60, 60)).getAllByRole('link')).toHaveLength(21);
});

it('works without the count when the theme ratings do not load', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  api.themeRatingsStatus = 503;
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  expect(screen.queryByText(/Scored/)).not.toBeInTheDocument();
  const strip = filmstrip(1, 2, 2);
  expect(within(strip).getByRole('link', { name: 'Frame 1' })).toHaveAttribute(
    'aria-current',
    'true',
  );
  expect(within(strip).getByRole('link', { name: 'Frame 2' })).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 11, rating: 8 }]);
});

it('announces the photograph and its score after moving', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('{ArrowRight}');
  await waitFor(() => expect(announcement()).toBe('#0012, 2 / 2, score 4'));
  await user.click(screen.getByRole('button', { name: 'Previous' }));
  await waitFor(() => expect(announcement()).toBe('#0011, 1 / 2, no score'));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await waitFor(() => expect(announcement()).toBe('#0012, 2 / 2, score 4'));
  await user.click(screen.getByRole('link', { name: 'Frame 1, unscored' }));
  await waitFor(() => expect(announcement()).toBe('#0011, 1 / 2, no score'));
});

it('announces the photograph alone when its rating does not load', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  api.failingSubmissionRatings.add(12);
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(announcement()).toBe('#0012, 2 / 2'));
});
