import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { FormEvent } from 'react';
import { MemoryRouter, useLocation, useNavigationType } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import Button, { ButtonBar, ButtonRow } from './Button';

describe('button', () => {
  it('is a secondary button named by its label by default', async () => {
    const onPress = vi.fn();
    render(<Button onPress={onPress}>Open contest</Button>);
    const button = screen.getByRole('button', { name: 'Open contest' });
    expect(button).toHaveClass('rl-btn', 'rl-btn--secondary');
    expect(button).toHaveAttribute('type', 'button');
    await userEvent.setup().click(button);
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it('activates with Enter and Space', async () => {
    const onPress = vi.fn();
    render(<Button onPress={onPress}>Save</Button>);
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Enter}');
    await user.keyboard(' ');
    expect(onPress).toHaveBeenCalledTimes(2);
  });

  it('carries the variant, size and block classes and a hidden leading icon', () => {
    render(
      <Button variant="primary" size="large" block icon="plus" type="submit">
        New contest
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'New contest' });
    expect(button).toHaveClass(
      'rl-btn',
      'rl-btn--primary',
      'rl-btn--large',
      'rl-btn--block',
    );
    expect(button).toHaveAttribute('type', 'submit');
    const icon = button.querySelector('svg');
    expect(icon).toHaveClass('rl-btn__icon');
    expect(icon).toHaveAttribute('aria-hidden', 'true');
  });

  it('submits its form', async () => {
    const onSubmit = vi.fn((event: FormEvent) => event.preventDefault());
    render(
      <form onSubmit={onSubmit}>
        <Button type="submit">Submit entry</Button>
      </form>,
    );
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Submit entry' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('passes the ARIA state and focus props to the button', () => {
    render(
      <>
        <p id="hint">Opens the account menu</p>
        <Button
          variant="quiet"
          aria-label="Account"
          aria-describedby="hint"
          aria-pressed
          aria-expanded={false}
          aria-haspopup="menu"
          autoFocus
        >
          AN
        </Button>
      </>,
    );
    const button = screen.getByRole('button', { name: 'Account' });
    expect(button).toHaveAccessibleDescription('Opens the account menu');
    expect(button).toHaveAttribute('aria-pressed', 'true');
    expect(button).toHaveAttribute('aria-expanded', 'false');
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
    expect(button).toHaveFocus();
  });

  it('names its keyboard shortcut and still activates', async () => {
    const onPress = vi.fn();
    render(
      <Button aria-keyshortcuts="ArrowRight" onPress={onPress}>
        Next
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Next' });
    expect(button).toHaveAttribute('aria-keyshortcuts', 'ArrowRight');
    expect(button).toHaveClass('rl-btn', 'rl-btn--secondary');
    await userEvent.setup().click(button);
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it('is a link, not a button, when it goes to another page', () => {
    render(
      <MemoryRouter>
        <Button to="/results" variant="quiet" icon="arrow-up-right">
          Results
        </Button>
      </MemoryRouter>,
    );
    const link = screen.getByRole('link', { name: 'Results' });
    expect(link).toHaveAttribute('href', '/results');
    expect(link).toHaveClass('rl-btn', 'rl-btn--quiet');
    expect(link.querySelector('svg')).toHaveClass('rl-btn__icon');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('replaces the history entry and passes router state when told to', async () => {
    function Here() {
      const location = useLocation();
      const navigationType = useNavigationType();
      return (
        <p>
          {location.pathname} {navigationType} {JSON.stringify(location.state)}
        </p>
      );
    }
    render(
      <MemoryRouter initialEntries={['/sign-in']}>
        <Button to="/login" replace state={{ from: '/results' }}>
          Go to login
        </Button>
        <Here />
      </MemoryRouter>,
    );
    await userEvent
      .setup()
      .click(screen.getByRole('link', { name: 'Go to login' }));
    expect(
      screen.getByText('/login REPLACE {"from":"/results"}'),
    ).toBeInTheDocument();
  });
});

describe('locked button', () => {
  function renderLocked(onPress = vi.fn(), onSubmit = vi.fn()) {
    render(
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <Button
          type="submit"
          variant="primary"
          onPress={onPress}
          locked={{ reason: '138 photos not scored yet' }}
        >
          Finish judging
        </Button>
      </form>,
    );
    return { onPress, onSubmit };
  }

  it('stays focusable, says why and ignores activation', async () => {
    const { onPress, onSubmit } = renderLocked();
    const button = screen.getByRole('button', { name: 'Finish judging' });
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).not.toBeDisabled();
    expect(button).toHaveAccessibleDescription('138 photos not scored yet');
    expect(button).toHaveClass('rl-btn', 'rl-btn--locked');
    expect(button).not.toHaveClass('rl-btn--primary');

    const user = userEvent.setup();
    await user.tab();
    expect(button).toHaveFocus();
    await user.keyboard('{Enter}');
    await user.click(button);
    expect(onPress).not.toHaveBeenCalled();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('shows the lock beside the label and the reason beside the button', () => {
    renderLocked();
    const button = screen.getByRole('button', { name: 'Finish judging' });
    expect(button.querySelector('svg')).toHaveClass('rl-btn__icon');
    const reason = screen.getByText('138 photos not scored yet');
    expect(reason).toHaveClass('rl-btn-reason');
    expect(reason.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
    expect(reason.parentElement).toHaveClass('rl-btn-row');
    expect(reason.parentElement).toContainElement(button);
  });

  it('keeps its own description after the reason', () => {
    render(
      <>
        <p id="more">Finish every theme first.</p>
        <Button locked={{ reason: 'Two themes left' }} aria-describedby="more">
          Publish results
        </Button>
      </>,
    );
    expect(
      screen.getByRole('button', { name: 'Publish results' }),
    ).toHaveAccessibleDescription('Two themes left Finish every theme first.');
  });

  it('keeps a shortcut while locked', async () => {
    const onPress = vi.fn();
    render(
      <Button
        aria-keyshortcuts="Enter"
        onPress={onPress}
        locked={{ reason: 'Not ready' }}
      >
        Finish
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Finish' });
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).toHaveAttribute('aria-keyshortcuts', 'Enter');
    await userEvent.setup().click(button);
    expect(onPress).not.toHaveBeenCalled();
  });
});

describe('inert button', () => {
  it('looks as usual, is announced as unavailable and ignores activation', async () => {
    const onPress = vi.fn();
    render(
      <Button variant="quiet" inert onPress={onPress}>
        Previous
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Previous' });
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).not.toBeDisabled();
    expect(button).toHaveClass('rl-btn--quiet');
    expect(button).not.toHaveClass('rl-btn--locked');
    const user = userEvent.setup();
    await user.tab();
    expect(button).toHaveFocus();
    await user.keyboard('{Enter}');
    await user.click(button);
    expect(onPress).not.toHaveBeenCalled();
  });
});

describe('button layout', () => {
  it('lays buttons out in a row', () => {
    const { container } = render(
      <ButtonRow>
        <Button>One</Button>
        <Button>Two</Button>
      </ButtonRow>,
    );
    expect(container.firstElementChild).toHaveClass('rl-btn-row');
    expect(screen.getAllByRole('button')).toHaveLength(2);
  });

  it('puts the note of the sticky bar above its button', () => {
    const { container } = render(
      <ButtonBar note="You can change your entry until 15 Nov 2026.">
        <Button variant="primary">Submit entry</Button>
      </ButtonBar>,
    );
    const bar = container.firstElementChild;
    expect(bar).toHaveClass('rl-btn-bar');
    const note = screen.getByText(
      'You can change your entry until 15 Nov 2026.',
    );
    expect(note).toHaveClass('rl-btn-bar__note', 'caption');
    expect(bar?.firstElementChild).toBe(note);
  });
});
