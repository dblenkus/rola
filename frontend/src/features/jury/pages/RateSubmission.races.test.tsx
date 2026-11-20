// Responses that arrive in another order than their requests were sent: a
// read that the server handled before a write but that answers after it,
// writes for several photographs at once, and writes that finish after the
// judge moved on.
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import { jurySubmission, rating } from '../../../test/fixtures';
import {
  exactText,
  pressedScore,
  renderRater,
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

const threeSubmissions = [...twoSubmissions, jurySubmission(13, 'Third')];

const requestFailed = 'Request failed. Please try again.';

const clearButton = () => screen.getByRole('button', { name: 'Clear' });

const frame = (name: string) =>
  within(screen.getByRole('navigation', { name: /^Photo sequence/ })).getByRole(
    'link',
    { name },
  );

const scoreKeysDisabled = () =>
  scores.every(
    (value) => scoreKey(value).getAttribute('aria-disabled') === 'true',
  );

it('keeps a saved score when a rating read that started before the save answers after it', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  api.holdReads = true;
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldReads()).toEqual([11]));
  expect(await screen.findByText(exactText('Scored 0 / 2'))).toBeVisible();

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  // The server handled the read before the save, so it answers unscored.
  api.releaseRead(11);
  await settle();
  expect(pressedScore()).toBe(8);
  expect(screen.getByText(exactText('Scored 1 / 2'))).toBeVisible();
  expect(frame('Frame 1, score 8')).toBeVisible();
  expect(clearButton()).not.toHaveAttribute('aria-disabled', 'true');

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(pressedScore()).toBe(0));
  expect(api.deletes).toEqual([11]);
});

it('keeps a cleared score cleared when a rating read that started before the clear answers after it', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 7)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(7));

  // Away and back while the reads are slow: the pad shows the score it
  // already knows while the new read of First is on its way.
  api.holdReads = true;
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldReads()).toEqual([12, 11]));
  expect(pressedScore()).toBe(7);

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(pressedScore()).toBe(0));
  // The server handled the read before the clear, so it answers with the
  // deleted rating.
  api.releaseRead(11);
  await settle();
  expect(pressedScore()).toBe(0);
  expect(clearButton()).toHaveAttribute('aria-disabled', 'true');
  expect(frame('Frame 1, unscored')).toBeVisible();

  await user.keyboard('{Backspace}');
  await settle();
  expect(api.deletes).toEqual([11]);
});

it('reads the rating again when a save fails while a read that started before it is pending', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  api.holdReads = true;
  api.holdWrites = true;
  api.writeStatus = 400;
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldReads()).toEqual([11]));

  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  api.release();
  expect(await screen.findByRole('alert')).toHaveTextContent(requestFailed);
  // The failed save gave no score, so the view asks the server again.
  await waitFor(() => expect(api.heldReads()).toEqual([11, 11]));
  api.releaseRead(11);
  api.releaseRead(11);
  await waitFor(() => expect(pressedScore()).toBe(4));
});

it('saves scores for the next photograph while the previous save is pending', async () => {
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  expect(await screen.findByText(exactText('Scored 0 / 3'))).toBeVisible();

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();
  expect(scoreKeysDisabled()).toBe(false);

  await user.keyboard('7');
  await waitFor(() => expect(api.heldWrites()).toBe(2));
  expect(api.saves).toEqual([
    { submission: 11, rating: 8 },
    { submission: 12, rating: 7 },
  ]);
  expect(scoreKeysDisabled()).toBe(true);

  api.release();
  await settle();
  expect(pressedScore()).toBe(0);
  api.release();
  await waitFor(() => expect(pressedScore()).toBe(7));
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.getByText(exactText('Scored 2 / 3'))).toBeVisible();
  expect(frame('Frame 1, score 8')).toBeVisible();
  expect(frame('Frame 2, score 7')).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(8));
});

it('clears the next photograph while the previous save is pending', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(api.heldWrites()).toBe(2));
  expect(api.writes()).toEqual([
    'PUT /judging/ratings/11',
    'DELETE /judging/ratings/12',
  ]);
  api.release();
  api.release();
  await waitFor(() => expect(pressedScore()).toBe(0));
  expect(screen.getByText(exactText('Scored 1 / 2'))).toBeVisible();
});

it('shows a photograph as busy on return while its save is pending', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();
  expect(scoreKeysDisabled()).toBe(true);
  await user.keyboard('5');
  await user.click(scoreKey(5));
  await settle();
  expect(api.saves).toEqual([{ submission: 11, rating: 8 }]);

  api.release();
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(scoreKeysDisabled()).toBe(false);
});

it('keeps a score given before the theme ratings answer', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  api.holdThemeReads = true;
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldThemeReads()).toBe(1));
  await settle();

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  // The server handled the theme-wide read before the save.
  api.releaseThemeRead();
  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();
  expect(frame('Frame 1, score 8')).toBeVisible();
  expect(frame('Frame 2, unscored')).toBeVisible();
});

it('keeps a score cleared before the theme ratings answer', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 7), rating(502, 12, 4)],
  });
  api.holdThemeReads = true;
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(7));

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(pressedScore()).toBe(0));
  api.releaseThemeRead();
  expect(await screen.findByText(exactText('Scored 1 / 2'))).toBeVisible();
  expect(frame('Frame 1, unscored')).toBeVisible();
  expect(frame('Frame 2, score 4')).toBeVisible();
});

it('shows a score saved after the judge moved on when the judge returns before its read answers', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  api.holdWrites = true;
  api.holdReads = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  api.release();
  await settle();

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldReads()).toEqual([12, 11]));
  expect(pressedScore()).toBe(8);
  expect(clearButton()).not.toHaveAttribute('aria-disabled', 'true');

  api.releaseRead(11);
  await settle();
  expect(pressedScore()).toBe(8);
});

it('shows a score cleared after the judge moved on as cleared when the judge returns', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 7)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(7));

  api.holdWrites = true;
  api.holdReads = true;
  await user.keyboard('{Backspace}');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  api.release();
  await settle();

  api.failingSubmissionRatings.add(11);
  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(api.heldReads()).toEqual([12, 11]));
  expect(pressedScore()).toBe(0);
  expect(clearButton()).toHaveAttribute('aria-disabled', 'true');
  expect(frame('Frame 1, unscored')).toBeVisible();

  // The read that failed started after the clear, so it is reported.
  api.releaseRead(11);
  expect(await screen.findByRole('alert')).toHaveTextContent(requestFailed);
  await user.keyboard('{Backspace}');
  await settle();
  expect(api.deletes).toEqual([11]);
});
