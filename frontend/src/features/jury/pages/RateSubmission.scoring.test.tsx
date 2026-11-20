import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link } from 'react-router';
import { beforeEach, expect, it } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import { jurySubmission, rating } from '../../../test/fixtures';
import {
  announcement,
  exactText,
  photoScore,
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

const requestFailed = 'Request failed. Please try again.';

it('saves a score from a score key and stays on the photograph', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.click(scoreKey(8));
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 11, rating: 8 }]);
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'Second' })).not.toBeInTheDocument();
  expect(within(photoScore()).getByText(exactText('1 / 2'))).toBeVisible();
});

it('saves a score from a digit key and stays on the photograph', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 11, rating: 8 }]);
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'Second' })).not.toBeInTheDocument();
});

it('gives 10 for the 0 key', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('0');
  await waitFor(() => expect(pressedScore()).toBe(10));
  expect(api.saves).toEqual([{ submission: 11, rating: 10 }]);
});

it('announces a saved score', async () => {
  serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('8');
  await waitFor(() => expect(announcement()).toBe('Score 8'));
});

it('disables the score keys while a save is pending', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();
  for (const value of scores) {
    expect(scoreKey(value)).not.toHaveAttribute('aria-disabled', 'true');
  }

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  for (const value of scores) {
    expect(scoreKey(value)).toHaveAttribute('aria-disabled', 'true');
  }

  api.release();
  await waitFor(() => expect(pressedScore()).toBe(8));
  for (const value of scores) {
    expect(scoreKey(value)).not.toHaveAttribute('aria-disabled', 'true');
  }
});

it('ignores Clear and Backspace while a save is pending', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{Backspace}');
  await user.click(screen.getByRole('button', { name: 'Clear' }));
  await settle();
  expect(api.writes()).toEqual(['POST /rating']);

  api.release();
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.writes()).toEqual(['POST /rating']);
});

// A clear is a write like a score: the server keeps whichever it handles
// last, so a score sent while a clear is pending could be lost.
it('ignores score keys and digits while a clear is pending', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  api.holdWrites = true;
  await user.keyboard('{Backspace}');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('8');
  await user.click(scoreKey(8));
  await settle();
  expect(api.writes()).toEqual(['DELETE /rating/501']);

  api.release();
  await waitFor(() => expect(pressedScore()).toBe(0));
  expect(api.writes()).toEqual(['DELETE /rating/501']);
});

it('keeps the previous score after a failed save', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  api.writeStatus = 400;
  await user.keyboard('8');
  expect(await screen.findByRole('alert')).toHaveTextContent(requestFailed);
  expect(pressedScore()).toBe(4);
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
});

it('clears a score with the Clear button', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.click(screen.getByRole('button', { name: 'Clear' }));
  await waitFor(() => expect(pressedScore()).toBe(0));
  expect(api.deletes).toEqual([501]);
  expect(screen.getByRole('button', { name: 'Clear' })).toHaveAttribute(
    'aria-disabled',
    'true',
  );
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
});

it('clears a score with Backspace', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(pressedScore()).toBe(0));
  expect(api.deletes).toEqual([501]);
});

it('announces a cleared score', async () => {
  serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.keyboard('{Backspace}');
  await waitFor(() => expect(announcement()).toBe('Score cleared'));
});

it('clears a score just given by the id of the saved rating', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  await user.keyboard('{Backspace}');
  await waitFor(() => expect(pressedScore()).toBe(0));
  // The fake API gives a new rating the id 901.
  expect(api.deletes).toEqual([901]);
});

it('keeps the score after a failed clear', async () => {
  const api = serveJudging({
    submissions: twoSubmissions,
    ratings: [rating(501, 11, 4)],
  });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  api.writeStatus = 400;
  await user.keyboard('{Backspace}');
  expect(await screen.findByRole('alert')).toHaveTextContent(requestFailed);
  expect(api.deletes).toEqual([501]);
  expect(pressedScore()).toBe(4);
});

it('sends nothing on Clear or Backspace for an unscored photograph', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await settle();

  await user.keyboard('{Backspace}');
  await user.click(screen.getByRole('button', { name: 'Clear' }));
  await settle();
  expect(api.writes()).toEqual([]);
  expect(screen.getByRole('img', { name: 'First' })).toBeVisible();
});

it('shows a score saved after the judge moved on when the judge returns', async () => {
  const api = serveJudging({ submissions: twoSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  api.holdWrites = true;
  await user.keyboard('8');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  api.release();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(pressedScore()).toBe(0);

  await user.keyboard('{ArrowLeft}');
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(8));
});

it('changes nothing in a rater opened after leaving through Back to theme', async () => {
  const api = serveJudging({
    submissions: [...twoSubmissions, jurySubmission(13, 'Third')],
  });
  const user = userEvent.setup();
  renderRater(store, {
    themePage: (
      <Link to="/judge/contest/1/theme/2/rate?submission=12">Open Second</Link>
    ),
  });
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();

  api.holdWrites = true;
  await user.keyboard('5');
  await waitFor(() => expect(api.heldWrites()).toBe(1));
  await user.click(screen.getByRole('link', { name: 'Back to theme' }));
  await user.click(await screen.findByRole('link', { name: 'Open Second' }));
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();

  api.release();
  await settle();
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(screen.queryByRole('img', { name: 'Third' })).not.toBeInTheDocument();
  expect(pressedScore()).toBe(0);
  expect(announcement()).not.toBe('Score 5');
});
