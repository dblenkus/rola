import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import headerReversedUrl from '../../design/logos/rola-logo-header-reversed.svg';
import headerUrl from '../../design/logos/rola-logo-header.svg';
import mark48Url from '../../design/logos/rola-mark-48.svg';
import smallUrl from '../../design/logos/rola-logo-small.svg';
import Logo from './Logo';

it('shows the header lockup at its native size, named Rola', () => {
  render(<Logo variant="header" />);
  const logo = screen.getByRole('img', { name: 'Rola' });
  expect(logo).toHaveAttribute('src', headerUrl);
  expect(logo).toHaveAttribute('width', '57');
  expect(logo).toHaveAttribute('height', '26');
});

it('selects the white header file when reversed', () => {
  render(<Logo variant="header" reversed />);
  expect(screen.getByRole('img', { name: 'Rola' })).toHaveAttribute(
    'src',
    headerReversedUrl,
  );
});

it('shows the small lockup 40 px tall and the mark at 48 px', () => {
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
});

it('leaves the image unnamed when a parent link names it', () => {
  render(
    <a href="/" aria-label="Rola, home">
      <Logo variant="header" decorative />
    </a>,
  );
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Rola, home' })).toBeInTheDocument();
});
