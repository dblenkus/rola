import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { describe, expect, it, vi } from 'vitest';
import Pagination from './Pagination';

// A pager as the admin's submission table uses it, with its translations.
function Pager({
  count,
  initialPage = 1,
  onRowsPerPageChange = vi.fn(),
}: {
  count: number;
  initialPage?: number;
  onRowsPerPageChange?: (rows: number) => void;
}) {
  const { t } = useTranslation();
  const [page, setPage] = useState(initialPage);
  const [rowsPerPage, setRowsPerPage] = useState(20);
  return (
    <Pagination
      count={count}
      page={page}
      rowsPerPage={rowsPerPage}
      rowsPerPageOptions={[1, 20, 50, 100]}
      onPageChange={setPage}
      onRowsPerPageChange={(rows) => {
        setRowsPerPage(rows);
        setPage(1);
        onRowsPerPageChange(rows);
      }}
      labelRowsPerPage={t('rows_per_page')}
      labelDisplayedRows={({ from, to, count: total }) =>
        t('displayed_rows', { from, to, total })
      }
    />
  );
}

describe('pagination', () => {
  it('is a named navigation that says which rows are shown', () => {
    render(<Pager count={21} />);
    expect(
      screen.getByRole('navigation', { name: 'Pages' }),
    ).toBeInTheDocument();
    expect(screen.getByText('1-20 of 21')).toBeInTheDocument();
  });

  it('moves to the next and the previous page', async () => {
    render(<Pager count={21} />);
    const user = userEvent.setup();
    const previous = screen.getByRole('button', {
      name: 'Go to previous page',
    });
    const next = screen.getByRole('button', { name: 'Go to next page' });
    expect(previous).toHaveAttribute('aria-disabled', 'true');
    expect(next).not.toHaveAttribute('aria-disabled');

    await user.click(next);
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    expect(next).toHaveAttribute('aria-disabled', 'true');
    expect(previous).not.toHaveAttribute('aria-disabled');

    await user.click(next);
    expect(screen.getByText('21-21 of 21')).toBeInTheDocument();
    await user.click(previous);
    expect(screen.getByText('1-20 of 21')).toBeInTheDocument();
  });

  it('keeps unavailable steps focusable', async () => {
    render(<Pager count={5} />);
    const user = userEvent.setup();
    await user.tab();
    await user.tab();
    expect(
      screen.getByRole('button', { name: 'Go to previous page' }),
    ).toHaveFocus();
    expect(screen.getByText('1-5 of 5')).toBeInTheDocument();
  });

  it('chooses the rows per page with a labelled select', async () => {
    const onRowsPerPageChange = vi.fn();
    render(<Pager count={60} onRowsPerPageChange={onRowsPerPageChange} />);
    const user = userEvent.setup();
    const select = screen.getByRole('combobox', { name: 'Rows per page:' });
    expect(select).toHaveValue('20');
    await user.selectOptions(select, '50');
    expect(onRowsPerPageChange).toHaveBeenCalledWith(50);
    expect(screen.getByText('1-50 of 60')).toBeInTheDocument();
  });

  it('shows no rows of an empty table', () => {
    render(<Pager count={0} />);
    expect(screen.getByText('0-0 of 0')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Go to next page' }),
    ).toHaveAttribute('aria-disabled', 'true');
  });

  it('shows the rows of the last page for a page past the end', () => {
    // As after the only row of the last page is deleted, until the list
    // moves to the page before it.
    render(<Pager count={20} initialPage={2} />);
    expect(screen.getByText('1-20 of 20')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Go to next page' }),
    ).toHaveAttribute('aria-disabled', 'true');
  });
});
