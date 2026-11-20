import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import Footer from './Footer';

it('is the contentinfo landmark with the year and the author', () => {
  render(<Footer />);
  expect(screen.getByRole('contentinfo')).toHaveTextContent(
    `${new Date().getFullYear()} - Domen Blenkuš`,
  );
});
