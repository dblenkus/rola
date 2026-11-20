import { createContext, useContext, type ReactNode } from 'react';
import './Table.css';

// Whether a cell sits in the table head, where a header cell heads a column
// rather than a row.
const InHead = createContext(false);

function joinClasses(...names: (string | undefined)[]): string {
  return names.filter(Boolean).join(' ');
}

// The explicit roles keep the table's semantics on phones, where its rows
// are laid out as stacked blocks.

interface TableProps {
  children: ReactNode;
  // The table's accessible name, where no heading right above names it.
  label?: string;
}

// A data table: hairline row dividers, no outer box, no zebra or hover fill.
// On phones each row becomes a block, and each cell shows its column label.
export default function Table({ children, label }: TableProps) {
  return (
    <table className="ui-table" role="table" aria-label={label}>
      {children}
    </table>
  );
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <InHead.Provider value={true}>
      <thead className="ui-table__head" role="rowgroup">
        {children}
      </thead>
    </InHead.Provider>
  );
}

export function TableBody({ children }: { children: ReactNode }) {
  return (
    <tbody className="ui-table__body" role="rowgroup">
      {children}
    </tbody>
  );
}

interface TableRowProps {
  children: ReactNode;
  // Added to the row's own class.
  className?: string;
}

export function TableRow({ children, className }: TableRowProps) {
  return (
    <tr className={joinClasses('ui-table__row', className)} role="row">
      {children}
    </tr>
  );
}

interface TableCellProps {
  children?: ReactNode;
  // Makes a body cell the head of its row. Every cell in TableHead is a
  // column head.
  header?: boolean;
  // The column's name, shown before the content on phones, where the head
  // row is hidden. A cell without one shows only its content.
  label?: string;
  align?: 'start' | 'center' | 'end';
  colSpan?: number;
  // Added to the cell's own classes.
  className?: string;
}

export function TableCell({
  children,
  header,
  label,
  align = 'start',
  colSpan,
  className: extraClassName,
}: TableCellProps) {
  const inHead = useContext(InHead);
  const className = joinClasses(
    'ui-table__cell',
    `ui-table__cell--${align}`,
    inHead ? 'mono-label' : 'body-dense',
    extraClassName,
  );
  if (inHead || header) {
    return (
      <th
        className={className}
        role={inHead ? 'columnheader' : 'rowheader'}
        scope={inHead ? 'col' : 'row'}
        colSpan={colSpan}
        data-label={label}
      >
        {children}
      </th>
    );
  }
  return (
    <td className={className} role="cell" colSpan={colSpan} data-label={label}>
      {children}
    </td>
  );
}
