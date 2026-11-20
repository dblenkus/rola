import { screen, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import '../../../app/i18n/config';
import { page, serveApi, signIn } from '../../../test/api';
import { open } from '../../../test/app';
import { contest, submission } from '../../../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  signIn();
  serveApi({
    'GET /contests': () => page([contest]),
    'GET /submissions': () => page([submission(11, 'Forest')]),
  });
});

it('labels each cell with its column for the phone layout', async () => {
  open('/user/submissions');
  const row = await screen.findByRole('row', { name: /Ana Novak/ });
  expect(
    within(row)
      .getAllByRole('cell')
      .map((cell) => cell.getAttribute('data-label')),
  ).toEqual([
    'Contest',
    'Author',
    'Number of themes',
    'Number of photos',
    null,
  ]);
  expect(
    screen.getByRole('heading', { level: 1, name: 'Edit submissions' }),
  ).toBeInTheDocument();
});

it('says once why an entry cannot be edited yet', async () => {
  open('/user/submissions');
  const edit = await screen.findByRole('button', { name: 'Edit' });
  expect(edit).toHaveAttribute('aria-disabled', 'true');
  expect(edit).toHaveAccessibleDescription(
    'Editing an entry is not available yet. To change one, delete it and upload it again.',
  );
  expect(
    screen.getAllByText(
      'Editing an entry is not available yet. To change one, delete it and upload it again.',
    ),
  ).toHaveLength(1);
});
