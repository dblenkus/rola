import { useId, useState } from 'react';
import { CalendarDate } from '@internationalized/date';
import {
  DateField as AriaDateField,
  DateInput,
  DateSegment,
  Label,
} from 'react-aria-components';
import Icon from './Icon';
import './DateField.css';

// The change a date field reports: the field's name and the chosen day, at
// local midnight.
interface DateChange {
  name: string;
  value: Date;
}

interface DateFieldProps {
  name: string;
  label: string;
  // The day, read from its local calendar fields; the time is ignored.
  value: Date | null;
  // The message that says what is wrong and how to fix it, or null.
  error: string | null;
  // Announced as required and marked " *"; the form's own validation
  // enforces it, as in ComboBoxField.
  required?: boolean;
  autoComplete: string;
  autoFocus?: boolean;
  // Called only with a complete date with a four-digit year, never while a
  // part is missing.
  onChange: (change: DateChange) => void;
}

// The local calendar day of a date, so no time zone shifts it.
function toCalendarDate(date: Date): CalendarDate {
  return new CalendarDate(
    date.getFullYear(),
    date.getMonth() + 1,
    date.getDate(),
  );
}

function sameDay(a: CalendarDate | null, b: CalendarDate | null): boolean {
  return a === null || b === null ? a === b : a.compare(b) === 0;
}

// A date typed as day, month and year segments in the order of the language
// (React Aria's I18nProvider, or the browser's language without one), such
// as the entrant's date of birth.
export default function DateField({
  name,
  label,
  value,
  error,
  required = false,
  autoComplete,
  autoFocus = false,
  onChange,
}: DateFieldProps) {
  const errorId = useId();
  const given = value === null ? null : toCalendarDate(value);
  // What the segments show. React Aria reports a date as soon as every
  // segment has a digit, so while the year is typed it reports the years 2,
  // 20 and 200 first; the field keeps those to itself.
  const [shown, setShown] = useState(given);
  // A new value from the form replaces whatever the segments show.
  const [lastGiven, setLastGiven] = useState(given);
  if (!sameDay(given, lastGiven)) {
    setLastGiven(given);
    setShown(given);
  }

  const handleChange = (date: CalendarDate | null): void => {
    setShown(date);
    if (date !== null && date.year >= 1000) {
      onChange({ name, value: new Date(date.year, date.month - 1, date.day) });
    }
  };

  return (
    <AriaDateField
      className={error === null ? 'rl-field' : 'rl-field rl-field--invalid'}
      name={name}
      value={shown}
      onChange={handleChange}
      granularity="day"
      validationBehavior="aria"
      isRequired={required}
      isInvalid={error !== null}
      autoComplete={autoComplete}
      autoFocus={autoFocus}
      {...(error === null ? {} : { 'aria-describedby': errorId })}
    >
      <Label className="rl-field__label">
        {label}
        {required && <span aria-hidden="true"> *</span>}
      </Label>
      <DateInput className="rl-field__input ui-datefield__input">
        {(segment) => (
          <DateSegment className="ui-datefield__segment" segment={segment} />
        )}
      </DateInput>
      {error !== null && (
        <span id={errorId} className="rl-field__error">
          <Icon name="alert" />
          {error}
        </span>
      )}
    </AriaDateField>
  );
}
