import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import Page from './Page';

it('gives the page one h1 and the document title', () => {
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
  // The shell focuses <main> after a navigation, not the heading.
  expect(heading).not.toHaveAttribute('tabindex');
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

it('shows content above the title', () => {
  render(
    <Page title="Sign in" width="narrow" before={<p>Logo</p>}>
      <p>Form</p>
    </Page>,
  );
  const before = screen.getByText('Logo');
  const heading = screen.getByRole('heading', { level: 1, name: 'Sign in' });
  expect(
    before.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  expect(before.closest('.ui-page')).not.toBeNull();
});

it('leaves the h1 to a page that places its own', () => {
  const { container } = render(
    <Page title="Bridges" ownHeading width="full">
      <h1>Bridges</h1>
    </Page>,
  );
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(container.querySelector('.ui-page__head')).toBeNull();
  expect(document.title).toBe('Bridges · Rola');
});

it('keeps the lead and actions of a page with its own h1', () => {
  render(
    <Page
      title="Bridges"
      ownHeading
      lead="Spring salon"
      actions={<button>Next</button>}
    >
      <h1>Bridges</h1>
    </Page>,
  );
  expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  expect(screen.getByText('Spring salon')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Next' })).toBeInTheDocument();
});

it('sets the lead in body type unless told otherwise', () => {
  const { rerender } = render(
    <Page title="Contest" lead="Entries close soon">
      {null}
    </Page>,
  );
  expect(screen.getByText('Entries close soon')).toHaveClass('body');
  rerender(
    <Page title="Contest" lead="Entries close soon" leadSize="small">
      {null}
    </Page>,
  );
  const lead = screen.getByText('Entries close soon');
  expect(lead).toHaveClass('small');
  expect(lead).not.toHaveClass('body');
});
