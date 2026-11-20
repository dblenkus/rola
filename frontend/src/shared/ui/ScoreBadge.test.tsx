import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import ScoreBadge from './ScoreBadge';

it('shows a scored photo as an inverted figure named by its label', () => {
  render(<ScoreBadge score={8} label="Score 8" size="lg" />);
  const badge = screen.getByRole('img', { name: 'Score 8' });
  expect(badge).toHaveTextContent(/^8$/);
  expect(badge).toHaveClass(
    'rl-score-badge',
    'rl-score-badge--scored',
    'rl-score-badge--lg',
  );
  expect(badge).not.toHaveClass('rl-score-badge--current');
});

it('shows an unscored photo as a dash, never as 0', () => {
  render(<ScoreBadge score={null} label="Unscored" />);
  const badge = screen.getByRole('img', { name: 'Unscored' });
  expect(badge).toHaveTextContent(/^–$/);
  expect(badge).toHaveClass('rl-score-badge--unscored');
});

it('marks the current photo', () => {
  render(<ScoreBadge score={10} label="Score 10, current" current />);
  expect(screen.getByRole('img', { name: 'Score 10, current' })).toHaveClass(
    'rl-score-badge--current',
  );
});

it('is hidden from assistive technology inside a link that names the score', () => {
  render(
    <a href="/judge/photo/276" aria-label="Frame 276, unscored">
      <ScoreBadge score={null} decorative />
    </a>,
  );
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(
    screen.getByRole('link', { name: 'Frame 276, unscored' }).firstElementChild,
  ).toHaveAttribute('aria-hidden', 'true');
});

it.each([0, 11, 7.5])('refuses the score %s', (score) => {
  expect(() => render(<ScoreBadge score={score} label="Score" />)).toThrow();
});
