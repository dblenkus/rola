import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import Message from './Message';

describe('message', () => {
  it('is announced as an alert with its text', () => {
    render(<Message severity="info">Judging opens on 1 December.</Message>);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('Judging opens on 1 December.');
    expect(alert).toHaveClass('ui-message', 'ui-message--info');
    expect(alert.querySelector('svg')).toBeNull();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('marks an error with the hidden alert icon', () => {
    render(
      <Message severity="error">Request failed. Please try again.</Message>,
    );
    const alert = screen.getByRole('alert');
    expect(alert).toHaveClass('ui-message--error');
    const icon = alert.querySelector('svg');
    expect(icon).toHaveAttribute('aria-hidden', 'true');
    expect(icon?.querySelector('circle')).not.toBeNull();
  });

  it('marks a warning with the alert icon and success with the check', () => {
    render(
      <>
        <Message severity="warning">The contest closes today.</Message>
        <Message severity="success">Saved.</Message>
      </>,
    );
    const [warning, success] = screen.getAllByRole('alert');
    expect(warning?.querySelector('circle')).not.toBeNull();
    expect(success?.querySelector('path')).toHaveAttribute(
      'd',
      'M3 8.5l3.25 3.25L13 5',
    );
  });

  it('closes with a named button', async () => {
    const onClose = vi.fn();
    render(
      <Message severity="success" onClose={onClose}>
        Saved.
      </Message>,
    );
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
