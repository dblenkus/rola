import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import Button from './Button';
import Icon from './Icon';
import './Pagination.css';

export interface DisplayedRows {
  from: number;
  to: number;
  count: number;
}

interface PaginationProps {
  // All rows, on every page.
  count: number;
  // The shown page, counted from 1.
  page: number;
  rowsPerPage: number;
  rowsPerPageOptions: number[];
  // Called with the page to show, counted from 1.
  onPageChange: (page: number) => void;
  onRowsPerPageChange: (rowsPerPage: number) => void;
  // Labels the rows-per-page choice.
  labelRowsPerPage: string;
  // Says which rows are shown, such as "21-40 of 52".
  labelDisplayedRows: (rows: DisplayedRows) => string;
}

// Moves through the pages of a table and chooses how many rows a page has.
// On phones it wraps onto two lines.
export default function Pagination({
  count,
  page,
  rowsPerPage,
  rowsPerPageOptions,
  onPageChange,
  onRowsPerPageChange,
  labelRowsPerPage,
  labelDisplayedRows,
}: PaginationProps) {
  const { t } = useTranslation();
  const selectId = useId();
  const pages = Math.max(1, Math.ceil(count / rowsPerPage));
  // A page past the end, as for a moment after the last page's only row is
  // deleted, is shown as the last page, so the range is never impossible.
  const shownPage = Math.min(page, pages);
  const from = count === 0 ? 0 : (shownPage - 1) * rowsPerPage + 1;
  const to = Math.min(shownPage * rowsPerPage, count);

  return (
    <nav className="ui-pagination" aria-label={t('ui_pagination')}>
      <span className="ui-pagination__rows">
        <label className="small" htmlFor={selectId}>
          {labelRowsPerPage}
        </label>
        <select
          id={selectId}
          className="ui-pagination__select body"
          value={rowsPerPage}
          onChange={({ target }) =>
            onRowsPerPageChange(parseInt(target.value, 10))
          }
        >
          {rowsPerPageOptions.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </span>
      <span className="ui-pagination__shown small">
        {labelDisplayedRows({ from, to, count })}
      </span>
      <span className="ui-pagination__steps">
        <Button
          variant="quiet"
          aria-label={t('ui_pagination_previous')}
          inert={page <= 1}
          onPress={() => onPageChange(page - 1)}
        >
          <Icon name="chevron-left" size={20} />
        </Button>
        <Button
          variant="quiet"
          aria-label={t('ui_pagination_next')}
          inert={page >= pages}
          onPress={() => onPageChange(page + 1)}
        >
          <Icon name="chevron-right" size={20} />
        </Button>
      </span>
    </nav>
  );
}
