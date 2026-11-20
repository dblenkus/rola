import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { I18nProvider } from 'react-aria-components';
import { describe, expect, it, vi } from 'vitest';
import DateField from './DateField';

function renderField({
  value = null,
  error = null,
  onChange = vi.fn(),
  locale = 'sl-SI',
}: {
  value?: Date | null;
  error?: string | null;
  onChange?: (change: { name: string; value: Date | null }) => void;
  locale?: string;
} = {}) {
  render(
    <I18nProvider locale={locale}>
      <DateField
        name="dob"
        label="Date of birth"
        value={value}
        error={error}
        required
        autoComplete="bday"
        onChange={onChange}
      />
    </I18nProvider>,
  );
  return onChange;
}

function segmentTypes(): (string | null)[] {
  return screen
    .getAllByRole('spinbutton')
    .map((segment) => segment.getAttribute('data-type'));
}

describe('date field', () => {
  it('is a group of segments named by the label', () => {
    renderField();
    const group = screen.getByRole('group', { name: 'Date of birth' });
    expect(group).toHaveClass('rl-field__input');
    const segments = within(group).getAllByRole('spinbutton');
    expect(segments).toHaveLength(3);
    for (const segment of segments) {
      expect(segment).toHaveAttribute('aria-required', 'true');
      expect(segment).toHaveAccessibleName(/Date of birth/);
    }
  });

  it('orders the segments by the language', () => {
    renderField({ locale: 'sl-SI' });
    expect(segmentTypes()).toEqual(['day', 'month', 'year']);
  });

  it('orders the segments by another language', () => {
    renderField({ locale: 'en-US' });
    expect(segmentTypes()).toEqual(['month', 'day', 'year']);
  });

  it('reports a typed date at local midnight once it is complete', async () => {
    const onChange = renderField();
    const user = userEvent.setup();
    const [day] = screen.getAllByRole('spinbutton');
    if (!day) throw new Error('The field has no segments');
    await user.click(day);
    await user.keyboard('04');
    await user.keyboard('03');
    expect(onChange).not.toHaveBeenCalled();
    await user.keyboard('2001');
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith({
      name: 'dob',
      value: new Date(2001, 2, 4),
    });
  });

  it('keeps the typed date when the form stores it', async () => {
    function StoredField() {
      const [value, setValue] = useState<Date | null>(null);
      return (
        <I18nProvider locale="sl-SI">
          <DateField
            name="dob"
            label="Date of birth"
            value={value}
            error={null}
            autoComplete="bday"
            onChange={(change) => setValue(change.value)}
          />
        </I18nProvider>
      );
    }
    render(<StoredField />);
    const user = userEvent.setup();
    const [day] = screen.getAllByRole('spinbutton');
    if (!day) throw new Error('The field has no segments');
    await user.click(day);
    await user.keyboard('04032001');
    await user.tab();
    expect(
      screen.getAllByRole('spinbutton').map((segment) => segment.textContent),
    ).toEqual(['4', '3', '2001']);
  });

  describe('after a date was given', () => {
    // A field whose form stores what it reports, starting from 4 March 2001.
    function renderStored() {
      const onChange = vi.fn();
      function StoredField() {
        const [value, setValue] = useState<Date | null>(new Date(2001, 2, 4));
        return (
          <I18nProvider locale="sl-SI">
            <DateField
              name="dob"
              label="Date of birth"
              value={value}
              error={null}
              autoComplete="bday"
              onChange={(change) => {
                onChange(change);
                setValue(change.value);
              }}
            />
          </I18nProvider>
        );
      }
      render(<StoredField />);
      const segments = screen.getAllByRole('spinbutton');
      const [day, month, year] = segments;
      if (!day || !month || !year) throw new Error('The field has no segments');
      return { onChange, day, month, year };
    }

    it('reports no date once the segments are cleared', async () => {
      const { onChange, year } = renderStored();
      const user = userEvent.setup();
      await user.click(year);
      await user.keyboard('{Backspace}{Backspace}{Backspace}{Backspace}');
      await user.keyboard('{Shift>}{Tab}{/Shift}{Backspace}');
      await user.keyboard('{Shift>}{Tab}{/Shift}{Backspace}');

      expect(onChange).toHaveBeenLastCalledWith({ name: 'dob', value: null });
      expect(
        screen.getAllByRole('spinbutton').map((segment) => segment.textContent),
      ).not.toContain('2001');
    });

    it('reports no date while the year is incomplete', async () => {
      const { onChange, year } = renderStored();
      const user = userEvent.setup();
      await user.click(year);
      await user.keyboard('198');

      expect(onChange).toHaveBeenLastCalledWith({ name: 'dob', value: null });
      // The segments keep what was typed.
      expect(year).toHaveTextContent('198');
    });

    it('reports the date again once the year is complete', async () => {
      const { onChange, year } = renderStored();
      const user = userEvent.setup();
      await user.click(year);
      await user.keyboard('1985');

      expect(onChange).toHaveBeenLastCalledWith({
        name: 'dob',
        value: new Date(1985, 2, 4),
      });
      expect(year).toHaveTextContent('1985');
    });
  });

  it('shows a date by its local calendar day', () => {
    renderField({ value: new Date(2001, 2, 4, 23, 30) });
    expect(
      screen.getAllByRole('spinbutton').map((segment) => segment.textContent),
    ).toEqual(['4', '3', '2001']);
  });

  it('describes an error and marks the segments invalid', () => {
    renderField({ error: 'Please enter the date of birth.' });
    const group = screen.getByRole('group', { name: 'Date of birth' });
    expect(group).toHaveAccessibleDescription(
      'Please enter the date of birth.',
    );
    expect(group.closest('.rl-field')).toHaveClass('rl-field--invalid');
    for (const segment of screen.getAllByRole('spinbutton')) {
      expect(segment).toHaveAttribute('aria-invalid', 'true');
    }
    const message = screen.getByText('Please enter the date of birth.');
    expect(message).toHaveClass('rl-field__error');
  });

  it('is valid without an error', () => {
    renderField();
    for (const segment of screen.getAllByRole('spinbutton')) {
      expect(segment).not.toHaveAttribute('aria-invalid');
    }
  });
});
