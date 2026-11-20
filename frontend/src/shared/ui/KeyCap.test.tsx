import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import KeyCap from './KeyCap';
import KeyLegend, { KeyLegendBreak, KeyLegendSeparator } from './KeyLegend';

it('shows a key as a kbd element', () => {
  render(
    <p>
      <KeyCap large>0</KeyCap> = 10
    </p>,
  );
  const key = screen.getByText('0');
  expect(key.tagName).toBe('KBD');
  expect(key).toHaveClass('rl-keycap', 'rl-keycap--large');
});

it('reads the legend as plain text in order, without the separators', () => {
  const { container } = render(
    <KeyLegend>
      <KeyCap>1–9</KeyCap>
      <span>score</span>
      <KeyLegendSeparator />
      <KeyCap>0</KeyCap>
      <span>= 10</span>
      <KeyLegendBreak />
      <KeyCap>Backspace</KeyCap>
      <span>clear</span>
    </KeyLegend>,
  );
  const legend = container.firstElementChild;
  expect(legend).toHaveClass('rl-keylegend');
  expect(legend).toHaveTextContent('1–9score·0= 10Backspaceclear');
  expect(screen.getByText('·')).toHaveAttribute('aria-hidden', 'true');
  expect(screen.getByText('1–9')).not.toHaveClass('rl-keycap--large');
});
