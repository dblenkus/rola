import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import ConfirmDialog from './ConfirmDialog';

function Confirmation({
  onClose = vi.fn(),
  onConfirm = vi.fn(),
}: {
  onClose?: () => void;
  onConfirm?: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Delete
      </button>
      <ConfirmDialog
        title="Delete the entry?"
        open={open}
        onClose={() => {
          setOpen(false);
          onClose();
        }}
        onConfirm={onConfirm}
      >
        Its photographs are removed too.
      </ConfirmDialog>
    </>
  );
}

async function openDialog() {
  const user = userEvent.setup();
  const trigger = screen.getByRole('button', { name: 'Delete' });
  await user.click(trigger);
  const dialog = await screen.findByRole('dialog', {
    name: 'Delete the entry?',
  });
  return { user, trigger, dialog };
}

describe('confirm dialog', () => {
  it('is a dialog named by its title that holds the focus', async () => {
    render(<Confirmation />);
    const { dialog } = await openDialog();
    expect(dialog).toHaveTextContent('Its photographs are removed too.');
    expect(
      within(dialog).getByRole('heading', { name: 'Delete the entry?' }),
    ).toBeInTheDocument();
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it('closes on "No" without confirming and returns the focus', async () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn();
    render(<Confirmation onClose={onClose} onConfirm={onConfirm} />);
    const { user, trigger, dialog } = await openDialog();
    await user.click(within(dialog).getByRole('button', { name: 'No' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('closes on Escape without confirming', async () => {
    const onConfirm = vi.fn();
    render(<Confirmation onConfirm={onConfirm} />);
    const { user } = await openDialog();
    await user.keyboard('{Escape}');
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('closes and then confirms on "Yes"', async () => {
    const calls: string[] = [];
    render(
      <Confirmation
        onClose={() => calls.push('close')}
        onConfirm={() => calls.push('confirm')}
      />,
    );
    const { user, dialog } = await openDialog();
    await user.click(within(dialog).getByRole('button', { name: 'Yes' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(calls).toEqual(['close', 'confirm']);
  });

  it('keeps the page behind it out of reach while open', async () => {
    render(<Confirmation />);
    const { trigger } = await openDialog();
    expect(
      screen.queryByRole('button', { name: 'Delete' }),
    ).not.toBeInTheDocument();
    expect(trigger.closest('[aria-hidden="true"], [inert]')).not.toBeNull();
  });
});
