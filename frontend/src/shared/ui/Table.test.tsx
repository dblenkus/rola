import { render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import Table, { TableBody, TableCell, TableHead, TableRow } from './Table';

it('renders a table with explicit roles and column heads', () => {
  render(
    <Table label="Your entries">
      <TableHead>
        <TableRow>
          <TableCell>Contest</TableCell>
          <TableCell>Photos</TableCell>
          <TableCell />
        </TableRow>
      </TableHead>
      <TableBody>
        <TableRow>
          <TableCell header label="Contest">
            Spring salon
          </TableCell>
          <TableCell label="Photos">6</TableCell>
          <TableCell align="end">
            <a href="/edit/1">Edit</a>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>,
  );
  const table = screen.getByRole('table', { name: 'Your entries' });
  expect(table.tagName).toBe('TABLE');
  expect(within(table).getAllByRole('rowgroup')).toHaveLength(2);
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  const heads = within(table).getAllByRole('columnheader');
  expect(heads.map((head) => head.textContent)).toEqual([
    'Contest',
    'Photos',
    '',
  ]);
  expect(heads[0]).toHaveAttribute('scope', 'col');
  const rowHead = within(table).getByRole('rowheader', {
    name: 'Spring salon',
  });
  expect(rowHead).toHaveAttribute('scope', 'row');
  const cells = within(table).getAllByRole('cell');
  // The phone label is an attribute, so a cell's text is only its content.
  expect(cells.map((cell) => cell.textContent)).toEqual(['6', 'Edit']);
  expect(cells[0]).toHaveAttribute('data-label', 'Photos');
  expect(cells[1]).not.toHaveAttribute('data-label');
  expect(cells[1]).toHaveClass('ui-table__cell--end');
});

it('spans columns in a table without a head', () => {
  render(
    <Table>
      <TableBody>
        <TableRow>
          <TableCell colSpan={3}>Landscapes</TableCell>
        </TableRow>
      </TableBody>
    </Table>,
  );
  expect(screen.queryByRole('columnheader')).not.toBeInTheDocument();
  expect(screen.getByRole('cell', { name: 'Landscapes' })).toHaveAttribute(
    'colspan',
    '3',
  );
});

it('adds the classes it is given to a row and its cells', () => {
  render(
    <Table>
      <TableHead>
        <TableRow>
          <TableCell className="entries-head">Title</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        <TableRow className="entries-row">
          <TableCell className="entries-title" align="end">
            Mist
          </TableCell>
          <TableCell header className="entries-author">
            Ana
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>,
  );
  expect(screen.getByRole('columnheader')).toHaveClass(
    'ui-table__cell',
    'mono-label',
    'entries-head',
  );
  expect(screen.getByRole('cell', { name: 'Mist' })).toHaveClass(
    'ui-table__cell',
    'ui-table__cell--end',
    'body-dense',
    'entries-title',
  );
  expect(screen.getByRole('rowheader', { name: 'Ana' })).toHaveClass(
    'ui-table__cell',
    'entries-author',
  );
  expect(screen.getAllByRole('row')[1]).toHaveClass(
    'ui-table__row',
    'entries-row',
  );
});
