import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import ResultsList from './ResultsList';

it('says where published results are found', () => {
  render(<ResultsList />);

  expect(
    screen.getByRole('heading', { level: 1, name: 'Results' }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(document.title).toBe('Results · Rola');
  expect(
    screen.getByText(
      "Once a contest's results are published, open them from the contest.",
    ),
  ).toBeInTheDocument();
});
