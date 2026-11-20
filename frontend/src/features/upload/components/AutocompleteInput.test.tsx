import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { page, serveApi } from '../../../test/api';
import type { Institution } from '../../../shared/api/types';
import AutocompleteField from './AutocompleteInput';

const school: Institution = {
  id: 1,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  name: 'Prule Primary School',
  kind: 1,
};

function renderField(value: string, onChange = vi.fn()) {
  render(
    <AutocompleteField
      name="school"
      label="School"
      value={value}
      error={null}
      required
      onChange={onChange}
    />,
  );
  return onChange;
}

describe('institution field', () => {
  it('shows a chosen institution before the list is loaded', () => {
    const adapter = serveApi({});
    renderField(school.name);
    expect(screen.getByRole('combobox', { name: 'School' })).toHaveValue(
      school.name,
    );
    expect(adapter).not.toHaveBeenCalled();
  });

  it('reports the chosen institution by name', async () => {
    serveApi({ 'GET /institutions': () => page([school]) });
    const user = userEvent.setup();
    const onChange = renderField('');
    await user.click(screen.getByRole('combobox', { name: 'School' }));
    await user.click(await screen.findByRole('option', { name: school.name }));
    expect(onChange).toHaveBeenCalledWith({
      name: 'school',
      value: school.name,
    });
  });
});
