import { useId, useState, type Key } from 'react';
import {
  ComboBox,
  Input,
  Label,
  ListBox,
  ListBoxItem,
  Popover,
  useFilter,
} from 'react-aria-components';
import { useTranslation } from 'react-i18next';
import Icon from './Icon';
import type { InputChange } from './TextField';
import './ComboBoxField.css';

interface ComboBoxFieldProps {
  name: string;
  label: string;
  // The chosen option, or '' for none. It is shown before the options load.
  value: string;
  // The message that says what is wrong and how to fix it, or null.
  error: string | null;
  // Announced as required and marked " *"; the form's own validation
  // enforces it (see the component's comment).
  required?: boolean;
  autoFocus?: boolean;
  // Reports a chosen option, and '' when the text is cleared.
  onChange: (change: InputChange) => void;
  // Loads the options the first time the list opens, and again on the next
  // opening after a failure.
  loadOptions: () => Promise<string[]>;
  // Shown under the field when the options could not be loaded.
  loadErrorMessage: string;
}

type Options =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'failed' }
  | { status: 'loaded'; names: string[] };

// A text field that suggests options from a list loaded on first use, such as
// the entrant's school. Only a chosen option or a cleared field is reported:
// text typed without choosing returns to the chosen option when the field is
// left.
//
// Validation is ARIA-only (aria-required, aria-invalid): React Aria's native
// mode would replace the browser's message bubble with a message in the
// browser's language under the field, and its invalid state would block the
// form from submitting while an error is shown.
export default function ComboBoxField({
  name,
  label,
  value,
  error,
  required = false,
  autoFocus = false,
  onChange,
  loadOptions,
  loadErrorMessage,
}: ComboBoxFieldProps) {
  const { t } = useTranslation();
  const errorId = useId();
  const { contains } = useFilter({ sensitivity: 'base' });
  const [options, setOptions] = useState<Options>({ status: 'idle' });
  const [inputValue, setInputValue] = useState(value);
  // A new value from the form replaces whatever text is in the field.
  const [shownValue, setShownValue] = useState(value);
  if (value !== shownValue) {
    setShownValue(value);
    setInputValue(value);
  }

  const handleOpenChange = (isOpen: boolean): void => {
    if (!isOpen || options.status === 'loading' || options.status === 'loaded')
      return;
    setOptions({ status: 'loading' });
    loadOptions().then(
      (names) => setOptions({ status: 'loaded', names: [...new Set(names)] }),
      () => setOptions({ status: 'failed' }),
    );
  };

  const handleInputChange = (text: string): void => {
    setInputValue(text);
    if (text === '' && value !== '') onChange({ name, value: '' });
  };

  // Called with an option when one is chosen, and when the field is left: with
  // the chosen option, or with null when that option is not among the loaded
  // ones (a kept value before the list loads). Either way the field shows the
  // chosen option again; clearing is reported by handleInputChange.
  const handleSelectionChange = (key: Key | null): void => {
    const chosen = key === null ? value : String(key);
    setInputValue(chosen);
    if (chosen !== value) onChange({ name, value: chosen });
  };

  const names = options.status === 'loaded' ? options.names : [];
  // The whole list while the field shows the chosen option, as when it opens.
  const shown =
    inputValue === value
      ? names
      : names.filter((option) => contains(option, inputValue));
  const shownError =
    error ?? (options.status === 'failed' ? loadErrorMessage : null);

  return (
    <ComboBox
      className={
        shownError === null ? 'rl-field' : 'rl-field rl-field--invalid'
      }
      name={name}
      items={shown.map((option) => ({ id: option }))}
      inputValue={inputValue}
      selectedKey={value === '' ? null : value}
      onInputChange={handleInputChange}
      onSelectionChange={handleSelectionChange}
      onOpenChange={handleOpenChange}
      menuTrigger="focus"
      // Opens on an empty list to say that options are loading or that none
      // match; after a failure the message under the field says why.
      allowsEmptyCollection={options.status !== 'failed'}
      validationBehavior="aria"
      isRequired={required}
      isInvalid={shownError !== null}
      autoFocus={autoFocus}
      {...(shownError === null ? {} : { 'aria-describedby': errorId })}
    >
      <Label className="rl-field__label">
        {label}
        {required && <span aria-hidden="true"> *</span>}
      </Label>
      <Input className="rl-field__input" />
      {shownError !== null && (
        <span id={errorId} className="rl-field__error">
          <Icon name="alert" />
          {shownError}
        </span>
      )}
      <Popover className="ui-combobox__popover" offset={4}>
        <ListBox
          className="ui-combobox__list"
          renderEmptyState={() => (
            <p className="ui-combobox__empty body">
              {options.status === 'loaded'
                ? t('ui_no_options')
                : t('ui_loading_options')}
            </p>
          )}
        >
          {({ id }: { id: string }) => (
            <ListBoxItem className="ui-combobox__option body" id={id}>
              {id}
            </ListBoxItem>
          )}
        </ListBox>
      </Popover>
    </ComboBox>
  );
}
