import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import Page from './Page';

it('gives the page one focusable h1 and the document title', () => {
  render(
    <Page
      title="Contests"
      lead="Open for entries"
      actions={<button>New contest</button>}
    >
      <p>Content</p>
    </Page>,
  );
  const heading = screen.getByRole('heading', { level: 1, name: 'Contests' });
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(heading).toHaveAttribute('tabindex', '-1');
  heading.focus();
  expect(heading).toHaveFocus();
  expect(document.title).toBe('Contests · Rola');
  expect(screen.getByText('Open for entries')).toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: 'New contest' }),
  ).toBeInTheDocument();
  expect(screen.getByText('Content')).toBeInTheDocument();
});

it('uses the standard width unless told otherwise', () => {
  const { container, rerender } = render(<Page title="Contests">{null}</Page>);
  expect(container.firstElementChild).toHaveClass(
    'ui-page',
    'ui-page--standard',
  );
  rerender(
    <Page title="Sign in" width="narrow">
      {null}
    </Page>,
  );
  expect(container.firstElementChild).toHaveClass('ui-page--narrow');
});

it('keeps a hidden title for assistive technology', () => {
  render(
    <Page title="Scoring" titleHidden>
      <p>Photo</p>
    </Page>,
  );
  const heading = screen.getByRole('heading', { level: 1, name: 'Scoring' });
  expect(heading).toHaveClass('visually-hidden');
  expect(document.title).toBe('Scoring · Rola');
});
