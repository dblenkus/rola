import { act, cleanup, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, expect, it } from 'vitest';
import { createAppStore, type AppStore } from '../../../app/store';
import { jurySubmission, rating } from '../../../test/fixtures';
import {
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

const threeSubmissions = [
  jurySubmission(11, 'First'),
  jurySubmission(12, 'Second'),
  jurySubmission(13, 'Third'),
];

const onSecond = '/judge/contest/1/theme/2/rate?submission=12';

const shortcutsButton = () =>
  screen.getByRole('button', { name: 'Keyboard shortcuts' });

it.each(['Control', 'Alt', 'Meta'])(
  'ignores the shortcuts while %s is held',
  async (modifier) => {
    const api = serveJudging({
      submissions: threeSubmissions,
      ratings: [rating(502, 12, 4)],
    });
    const user = userEvent.setup();
    renderRater(store, { path: onSecond });
    expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
    await waitFor(() => expect(pressedScore()).toBe(4));

    for (const key of [
      '8',
      '0',
      '{Backspace}',
      '{ArrowLeft}',
      '{ArrowRight}',
    ]) {
      await user.keyboard(`{${modifier}>}${key}{/${modifier}}`);
    }
    await settle();
    expect(api.writes()).toEqual([]);
    expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
    expect(pressedScore()).toBe(4);

    await user.keyboard('8');
    await waitFor(() => expect(pressedScore()).toBe(8));
    expect(api.saves).toEqual([{ submission: 12, rating: 8 }]);
  },
);

it.each<[string, ReactNode]>([
  ['text input', <input key="field" aria-label="Notes" />],
  ['textarea', <textarea key="field" aria-label="Notes" />],
  [
    'select',
    <select key="field" aria-label="Notes">
      <option>One</option>
      <option>Two</option>
    </select>,
  ],
  [
    'contenteditable element',
    <div
      key="field"
      aria-label="Notes"
      role="textbox"
      contentEditable
      suppressContentEditableWarning
      tabIndex={0}
    />,
  ],
])('ignores the shortcuts while focus is in a %s', async (_kind, field) => {
  const api = serveJudging({
    submissions: threeSubmissions,
    ratings: [rating(502, 12, 4)],
  });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond, beside: field });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await waitFor(() => expect(pressedScore()).toBe(4));

  await user.click(screen.getByLabelText('Notes'));
  await user.keyboard('80{Backspace}{ArrowLeft}{ArrowRight}');
  await settle();
  expect(api.writes()).toEqual([]);
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
  expect(pressedScore()).toBe(4);

  // Out of the field, the same keys work again.
  await user.tab();
  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 12, rating: 8 }]);
});

it('turns the shortcuts off and keeps the buttons working', async () => {
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'true');

  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  await user.keyboard('8{ArrowLeft}{ArrowRight}');
  await settle();
  expect(api.writes()).toEqual([]);
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();

  await user.click(scoreKey(8));
  await waitFor(() => expect(pressedScore()).toBe(8));
  await user.keyboard('{Backspace}');
  await settle();
  expect(api.writes()).toEqual(['PUT /judging/ratings/12']);
  expect(pressedScore()).toBe(8);

  await user.click(screen.getByRole('button', { name: 'Clear' }));
  await waitFor(() => expect(pressedScore()).toBe(0));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(await screen.findByRole('img', { name: 'Third' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Previous' }));
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
});

it('names no keyboard shortcuts on the controls while the shortcuts are off', async () => {
  serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();
  const controls = () => [
    ...scores.map((value) => scoreKey(value)),
    ...['Clear', 'Previous', 'Next'].map((name) =>
      screen.getByRole('button', { name }),
    ),
  ];
  for (const control of controls()) {
    expect(control).toHaveAttribute('aria-keyshortcuts');
  }

  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  for (const control of controls()) {
    expect(control).not.toHaveAttribute('aria-keyshortcuts');
  }

  await user.click(shortcutsButton());
  for (const control of controls()) {
    expect(control).toHaveAttribute('aria-keyshortcuts');
  }
});

it('marks the shortcuts switch with a check only while they are on', async () => {
  serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  const check = () =>
    shortcutsButton().querySelector('svg[aria-hidden="true"]');
  expect(check()).not.toBeNull();

  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  expect(check()).toBeNull();

  await user.click(shortcutsButton());
  expect(check()).not.toBeNull();
});

it('turns the shortcuts back on', async () => {
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();

  await user.click(shortcutsButton());
  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'true');
  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 12, rating: 8 }]);
});

it('keeps the shortcuts off in a rater opened later', async () => {
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  cleanup();

  renderRater(createAppStore(), { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  await user.keyboard('8{ArrowRight}');
  await settle();
  expect(api.writes()).toEqual([]);
  expect(screen.getByRole('img', { name: 'Second' })).toBeVisible();
});

it('keeps the shortcuts on in a rater opened after turning them back on', async () => {
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await user.click(shortcutsButton());
  await user.click(shortcutsButton());
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'true');
  cleanup();

  renderRater(createAppStore(), { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'true');
  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(api.saves).toEqual([{ submission: 12, rating: 8 }]);
});

it('starts with the shortcuts off when the stored choice is off', async () => {
  localStorage.setItem('rola.judge.shortcuts', 'off');
  const api = serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store, { path: onSecond });
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();

  expect(shortcutsButton()).toHaveAttribute('aria-pressed', 'false');
  await user.keyboard('8');
  await settle();
  expect(api.writes()).toEqual([]);
});

it('keeps focus where it is when a digit scores or an arrow moves', async () => {
  serveJudging({ submissions: threeSubmissions });
  const user = userEvent.setup();
  renderRater(store);
  expect(await screen.findByRole('img', { name: 'First' })).toBeVisible();
  const back = screen.getByRole('link', { name: 'Back to theme' });
  act(() => back.focus());

  await user.keyboard('8');
  await waitFor(() => expect(pressedScore()).toBe(8));
  expect(back).toHaveFocus();
  await user.keyboard('{ArrowRight}');
  expect(await screen.findByRole('img', { name: 'Second' })).toBeVisible();
  await settle();
  expect(back).toHaveFocus();
});
