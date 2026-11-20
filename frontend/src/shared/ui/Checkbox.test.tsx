import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import Checkbox from './Checkbox';

function ControlledCheckbox({
  onChange,
  hideLabel = false,
}: {
  onChange: (isSelected: boolean) => void;
  hideLabel?: boolean;
}) {
  const [isSelected, setSelected] = useState(false);
  return (
    <Checkbox
      label="Paid"
      hideLabel={hideLabel}
      isSelected={isSelected}
      onChange={(selected) => {
        setSelected(selected);
        onChange(selected);
      }}
    />
  );
}

describe('checkbox', () => {
  it('is named by its visible label and reports each change', async () => {
    const onChange = vi.fn();
    render(<ControlledCheckbox onChange={onChange} />);
    const checkbox = screen.getByRole('checkbox', { name: 'Paid' });
    expect(checkbox).not.toBeChecked();
    expect(screen.getByText('Paid')).toBeVisible();

    const user = userEvent.setup();
    await user.click(screen.getByText('Paid'));
    expect(checkbox).toBeChecked();
    expect(onChange).toHaveBeenLastCalledWith(true);
    await user.keyboard(' ');
    expect(checkbox).not.toBeChecked();
    expect(onChange).toHaveBeenLastCalledWith(false);
  });

  it('draws the check only when selected', () => {
    const { container, rerender } = render(
      <Checkbox label="Paid" isSelected={false} onChange={vi.fn()} />,
    );
    const box = container.querySelector('.ui-checkbox__box');
    expect(box).toHaveAttribute('aria-hidden', 'true');
    expect(box?.querySelector('svg')).toBeNull();
    rerender(<Checkbox label="Paid" isSelected onChange={vi.fn()} />);
    expect(screen.getByRole('checkbox', { name: 'Paid' })).toBeChecked();
    expect(container.querySelector('.ui-checkbox')).toHaveAttribute(
      'data-selected',
      'true',
    );
    expect(box?.querySelector('svg')).not.toBeNull();
  });

  it('keeps a hidden label as its name', () => {
    render(<ControlledCheckbox onChange={vi.fn()} hideLabel />);
    expect(screen.getByRole('checkbox', { name: 'Paid' })).toBeInTheDocument();
    expect(screen.queryByText('Paid')).not.toBeInTheDocument();
  });

  it('ignores activation when disabled', async () => {
    const onChange = vi.fn();
    render(
      <Checkbox
        label="Paid"
        isSelected={false}
        isDisabled
        onChange={onChange}
      />,
    );
    const checkbox = screen.getByRole('checkbox', { name: 'Paid' });
    expect(checkbox).toBeDisabled();
    await userEvent.setup().click(screen.getByText('Paid'));
    expect(onChange).not.toHaveBeenCalled();
  });
});
