import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import ComboBoxField from './ComboBoxField';
import type { InputChange } from './TextField';

const schools = [
  'Prule Primary School',
  'Ledina Primary School',
  'Vič Grammar',
];

function Field({
  initial = '',
  error = null,
  loadOptions = () => Promise.resolve(schools),
  onChange = vi.fn(),
}: {
  initial?: string;
  error?: string | null;
  loadOptions?: () => Promise<string[]>;
  onChange?: (change: InputChange) => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <ComboBoxField
      name="school"
      label="School"
      value={value}
      error={error}
      required
      loadOptions={loadOptions}
      loadErrorMessage="Could not load schools."
      onChange={(change) => {
        setValue(change.value);
        onChange(change);
      }}
    />
  );
}

describe('combo box field', () => {
  it('shows a kept value without loading the options', () => {
    const loadOptions = vi.fn(() => Promise.resolve(schools));
    render(<Field initial="Vič Grammar" loadOptions={loadOptions} />);
    const input = screen.getByRole('combobox', { name: 'School' });
    expect(input).toHaveValue('Vič Grammar');
    expect(input).toHaveClass('rl-field__input');
    expect(input).toBeRequired();
    expect(loadOptions).not.toHaveBeenCalled();
  });

  it('loads the options when the list first opens and says so meanwhile', async () => {
    let finish: (names: string[]) => void = () => undefined;
    const loadOptions = vi.fn(
      () =>
        new Promise<string[]>((resolve) => {
          finish = resolve;
        }),
    );
    render(<Field loadOptions={loadOptions} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('combobox', { name: 'School' }));
    expect(await screen.findByText('Loading options…')).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    finish(schools);
    expect(
      await screen.findByRole('option', { name: 'Ledina Primary School' }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole('option')).toHaveLength(3);

    await user.keyboard('{Escape}');
    await user.tab();
    await user.click(screen.getByRole('combobox', { name: 'School' }));
    expect(await screen.findAllByRole('option')).toHaveLength(3);
    expect(loadOptions).toHaveBeenCalledTimes(1);
  });

  it('reports a chosen option by name', async () => {
    const onChange = vi.fn();
    render(<Field onChange={onChange} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await user.click(
      await screen.findByRole('option', { name: 'Vič Grammar' }),
    );
    expect(onChange).toHaveBeenCalledWith({
      name: 'school',
      value: 'Vič Grammar',
    });
    expect(input).toHaveValue('Vič Grammar');
  });

  it('filters the options by the typed text', async () => {
    render(<Field />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await screen.findAllByRole('option');
    await user.type(input, 'primary');
    expect(screen.getAllByRole('option')).toHaveLength(2);
    await user.clear(input);
    await user.type(input, 'nowhere');
    expect(await screen.findByText('No options')).toBeInTheDocument();
  });

  it('shows the whole list when it opens on a kept value', async () => {
    render(<Field initial="Vič Grammar" />);
    await userEvent
      .setup()
      .click(screen.getByRole('combobox', { name: 'School' }));
    expect(await screen.findAllByRole('option')).toHaveLength(3);
  });

  it('reports a cleared field', async () => {
    const onChange = vi.fn();
    render(<Field initial="Vič Grammar" onChange={onChange} />);
    const user = userEvent.setup();
    await user.clear(screen.getByRole('combobox', { name: 'School' }));
    expect(onChange).toHaveBeenCalledWith({ name: 'school', value: '' });
  });

  it('puts back the chosen option when typed text is left unchosen', async () => {
    const onChange = vi.fn();
    render(<Field initial="Vič Grammar" onChange={onChange} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await screen.findAllByRole('option');
    await user.keyboard('{Backspace}{Backspace}');
    await user.tab();
    expect(input).toHaveValue('Vič Grammar');
    expect(onChange).not.toHaveBeenCalled();
  });

  it('keeps a kept value when the field is left before the options load', async () => {
    const loadOptions = vi.fn(() => new Promise<string[]>(() => undefined));
    render(<Field initial="Vič Grammar" loadOptions={loadOptions} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await user.tab();
    expect(input).toHaveValue('Vič Grammar');
  });

  it('describes a load failure and loads again on the next opening', async () => {
    const loadOptions = vi
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(schools);
    render(<Field loadOptions={loadOptions} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    const message = await screen.findByText('Could not load schools.');
    expect(message).toHaveClass('rl-field__error');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Could not load schools.');

    await user.tab();
    await user.click(input);
    expect(await screen.findAllByRole('option')).toHaveLength(3);
    expect(loadOptions).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(
        screen.queryByText('Could not load schools.'),
      ).not.toBeInTheDocument(),
    );
    expect(input).not.toHaveAttribute('aria-invalid');
  });

  it('loads again when text is typed after a failure', async () => {
    const loadOptions = vi
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(schools);
    render(<Field loadOptions={loadOptions} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await screen.findByText('Could not load schools.');

    await user.keyboard('vič');
    expect(
      await screen.findByRole('option', { name: 'Vič Grammar' }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(loadOptions).toHaveBeenCalledTimes(2);
    expect(
      screen.queryByText('Could not load schools.'),
    ).not.toBeInTheDocument();
  });

  it('loads again when the focused field is clicked after a failure', async () => {
    const loadOptions = vi
      .fn<() => Promise<string[]>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(schools);
    render(<Field loadOptions={loadOptions} />);
    const user = userEvent.setup();
    const input = screen.getByRole('combobox', { name: 'School' });
    await user.click(input);
    await screen.findByText('Could not load schools.');

    await user.click(input);
    expect(await screen.findAllByRole('option')).toHaveLength(3);
    expect(input).toHaveFocus();
    expect(loadOptions).toHaveBeenCalledTimes(2);
  });

  it('caps the height of a long list, which then scrolls', async () => {
    const many = Array.from({ length: 40 }, (_, index) => `School ${index}`);
    render(<Field loadOptions={() => Promise.resolve(many)} />);
    await userEvent
      .setup()
      .click(screen.getByRole('combobox', { name: 'School' }));
    const list = await screen.findByRole('listbox');
    const popover = list.closest('.ui-combobox__popover');
    if (!(popover instanceof HTMLElement)) {
      throw new Error('The list is not in its popover');
    }
    // React Aria writes the popover's max-height inline, over the style
    // sheet's; the cap must come through it.
    await waitFor(() => expect(popover.style.maxHeight).toBe('320px'));
  });

  it('describes an error and marks the field invalid', () => {
    render(<Field error="Please enter the school." />);
    const input = screen.getByRole('combobox', { name: 'School' });
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Please enter the school.');
    expect(input.closest('.rl-field')).toHaveClass(
      'rl-field',
      'rl-field--invalid',
    );
  });
});
