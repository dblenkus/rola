import { useId, type ChangeEvent, type HTMLAttributes } from 'react';
import Icon from './Icon';
import './TextField.css';

// The change a text field reports: the field's name and its new value.
export interface InputChange {
  name: string;
  value: string;
}

interface TextFieldProps {
  name: string;
  // Names the field, also when it is hidden.
  label: string;
  value: string;
  // The message that says what is wrong and how to fix it, or null.
  error: string | null;
  onChange: (change: InputChange) => void;
  type?: string;
  autoComplete?: string;
  inputMode?: HTMLAttributes<HTMLInputElement>['inputMode'];
  // Keeps the browser's own check on submit and marks the label with " *",
  // which is hidden from assistive technology since the field says it is
  // required.
  required?: boolean;
  autoFocus?: boolean;
  // Above 1, a text area with that many rows.
  rows?: number;
  placeholder?: string;
  // Keeps the label for screen readers only, where something else on screen
  // labels the field (a photo beside its title field).
  hideLabel?: boolean;
  // Helper text under the field, read as its description.
  description?: string;
}

// A labelled text input, or a text area, with its error under it.
export default function TextField({
  name,
  label,
  value,
  error,
  onChange,
  type = 'text',
  autoComplete,
  inputMode,
  required = false,
  autoFocus = false,
  rows = 1,
  placeholder,
  hideLabel = false,
  description,
}: TextFieldProps) {
  const id = useId();
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;
  const describedBy =
    [description && descriptionId, error !== null && errorId]
      .filter(Boolean)
      .join(' ') || undefined;
  const shared = {
    id,
    name,
    value,
    required,
    autoFocus,
    autoComplete,
    placeholder,
    'aria-invalid': error !== null || undefined,
    'aria-describedby': describedBy,
    onChange: ({
      target,
    }: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      onChange({ name, value: target.value });
    },
  };

  return (
    <div className={error === null ? 'rl-field' : 'rl-field rl-field--invalid'}>
      <label
        className={
          hideLabel
            ? 'rl-field__label rl-field__label--hidden'
            : 'rl-field__label'
        }
        htmlFor={id}
      >
        {label}
        {required && <span aria-hidden="true"> *</span>}
      </label>
      {rows > 1 ? (
        <textarea
          className="rl-field__input ui-textarea"
          rows={rows}
          {...shared}
        />
      ) : (
        <input
          className="rl-field__input"
          type={type}
          inputMode={inputMode}
          {...shared}
        />
      )}
      {description && (
        <span id={descriptionId} className="ui-field__description caption">
          {description}
        </span>
      )}
      {error !== null && (
        <span id={errorId} className="rl-field__error">
          <Icon name="alert" />
          {error}
        </span>
      )}
    </div>
  );
}
