import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import headerReversedUrl from '../../design/logos/rola-logo-header-reversed.svg';
import headerUrl from '../../design/logos/rola-logo-header.svg';
import mark48Url from '../../design/logos/rola-mark-48.svg';
import smallUrl from '../../design/logos/rola-logo-small.svg';
import Logo from './Logo';

// jsdom applies no style sheet, so both header files are in its tree; in a
// browser the one for the other ground has display: none and is in neither
// the rendering nor the accessibility tree. scripts/design.test.ts checks
// the rules behind the two classes.
it('renders both header files at their native size, named Rola, each shown on its ground', () => {
  render(<Logo variant="header" />);
  const [ink, reversed, ...rest] = screen.getAllByRole('img', { name: 'Rola' });
  expect(rest).toEqual([]);
  expect(ink).toHaveAttribute('src', headerUrl);
  expect(ink).toHaveClass('rl-logo', 'ui-logo--ink');
  expect(reversed).toHaveAttribute('src', headerReversedUrl);
  expect(reversed).toHaveClass('rl-logo', 'ui-logo--reversed');
  for (const file of [ink, reversed]) {
    expect(file).toHaveAttribute('width', '57');
    expect(file).toHaveAttribute('height', '26');
  }
});

it('renders only the white header file, always shown, when reversed', () => {
  render(<Logo variant="header" reversed />);
  const logo = screen.getByRole('img', { name: 'Rola' });
  expect(logo).toHaveAttribute('src', headerReversedUrl);
  expect(logo).toHaveAttribute('class', 'rl-logo');
});

it('shows the small lockup 40 px tall and the mark at 48 px, on a light ground only', () => {
  render(
    <>
      <Logo variant="small" />
      <Logo variant="mark" />
    </>,
  );
  const [small, mark] = screen.getAllByRole('img', { name: 'Rola' });
  expect(small).toHaveAttribute('src', smallUrl);
  expect(small).toHaveAttribute('height', '40');
  expect(mark).toHaveAttribute('src', mark48Url);
  expect(mark).toHaveAttribute('width', '48');
  expect(mark).toHaveAttribute('height', '48');
  for (const file of [small, mark]) {
    expect(file).toHaveClass('ui-logo--ink');
  }
});

it('leaves both header files unnamed when a parent link names it', () => {
  const { container } = render(
    <a href="/" aria-label="Rola, home">
      <Logo variant="header" decorative />
    </a>,
  );
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  const files = container.querySelectorAll('img');
  expect(files).toHaveLength(2);
  for (const file of files) {
    expect(file).toHaveAttribute('alt', '');
  }
  expect(screen.getByRole('link', { name: 'Rola, home' })).toBeInTheDocument();
});
