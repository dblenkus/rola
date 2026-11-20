import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import TextField, { type InputChange } from './TextField';

function ControlledField({
  onChange,
}: {
  onChange: (change: InputChange) => void;
}) {
  const [value, setValue] = useState('');
  return (
    <TextField
      name="title"
      label="Photo title"
      value={value}
      error={null}
      onChange={(change) => {
        setValue(change.value);
        onChange(change);
      }}
    />
  );
}

describe('text field', () => {
  it('is named by its label and reports each change with its name', async () => {
    const onChange = vi.fn();
    render(<ControlledField onChange={onChange} />);
    const input = screen.getByRole('textbox', { name: 'Photo title' });
    expect(input).toHaveClass('rl-field__input');
    expect(input).toHaveAttribute('name', 'title');
    await userEvent.setup().type(input, 'Fog');
    expect(input).toHaveValue('Fog');
    expect(onChange).toHaveBeenLastCalledWith({ name: 'title', value: 'Fog' });
  });

  it('describes an error, marks the field invalid and shows the alert icon', () => {
    const { container } = render(
      <TextField
        name="title"
        label="Photo title"
        value=""
        error="A title is required."
        onChange={vi.fn()}
      />,
    );
    const input = screen.getByRole('textbox', { name: 'Photo title' });
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('A title is required.');
    expect(container.firstElementChild).toHaveClass(
      'rl-field',
      'rl-field--invalid',
    );
    const message = screen.getByText('A title is required.');
    expect(message).toHaveClass('rl-field__error');
    expect(message.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
  });

  it('is valid without an error', () => {
    const { container } = render(
      <TextField
        name="title"
        label="Photo title"
        value="Fog"
        error={null}
        onChange={vi.fn()}
      />,
    );
    const input = screen.getByRole('textbox', { name: 'Photo title' });
    expect(input).not.toHaveAttribute('aria-invalid');
    expect(input).not.toHaveAttribute('aria-describedby');
    expect(container.firstElementChild).not.toHaveClass('rl-field--invalid');
  });

  it('keeps the native required check and the bare label as its name', () => {
    render(
      <TextField
        name="email"
        label="Email"
        value=""
        error={null}
        type="email"
        autoComplete="email"
        inputMode="email"
        required
        onChange={vi.fn()}
      />,
    );
    const input = screen.getByRole('textbox', { name: 'Email' });
    expect(input).toBeRequired();
    expect(input).toHaveAttribute('type', 'email');
    expect(input).toHaveAttribute('autocomplete', 'email');
    expect(input).toHaveAttribute('inputmode', 'email');
    expect(screen.getByText('Email', { selector: 'label' })).toHaveTextContent(
      'Email *',
    );
  });

  it('reads a description, followed by the error', () => {
    render(
      <TextField
        name="title"
        label="Photo title"
        value=""
        error="A title is required."
        description="Shown under the photo."
        onChange={vi.fn()}
      />,
    );
    expect(
      screen.getByRole('textbox', { name: 'Photo title' }),
    ).toHaveAccessibleDescription(
      'Shown under the photo. A title is required.',
    );
  });

  it('keeps a hidden label as the name', () => {
    render(
      <TextField
        name="title"
        label="Title of photo 01"
        value=""
        error={null}
        placeholder="Add a title"
        hideLabel
        onChange={vi.fn()}
      />,
    );
    const input = screen.getByRole('textbox', { name: 'Title of photo 01' });
    expect(input).toHaveAttribute('placeholder', 'Add a title');
    expect(
      screen.getByText('Title of photo 01', { selector: 'label' }),
    ).toHaveClass('rl-field__label', 'rl-field__label--hidden');
  });

  it('is a text area with more than one row', async () => {
    const onChange = vi.fn();
    render(
      <TextField
        name="description"
        label="Description"
        value=""
        error={null}
        rows={4}
        autoFocus
        onChange={onChange}
      />,
    );
    const area = screen.getByRole('textbox', { name: 'Description' });
    expect(area.tagName).toBe('TEXTAREA');
    expect(area).toHaveAttribute('rows', '4');
    expect(area).toHaveClass('rl-field__input', 'ui-textarea');
    expect(area).toHaveFocus();
    await userEvent.setup().keyboard('A');
    expect(onChange).toHaveBeenCalledWith({ name: 'description', value: 'A' });
  });

  it('lets the browser stop a form with a required field left empty', async () => {
    const onSubmit = vi.fn((event: SubmitEvent) => event.preventDefault());
    const { container } = render(
      <form>
        <TextField
          name="email"
          label="Email"
          value=""
          error={null}
          required
          onChange={vi.fn()}
        />
        <button type="submit">Send</button>
      </form>,
    );
    container.querySelector('form')?.addEventListener('submit', onSubmit);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Send' }));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('textbox', { name: 'Email' })).toBeInvalid();
  });
});
