import { Checkbox as AriaCheckbox } from 'react-aria-components';
import Icon from './Icon';
import './Checkbox.css';

interface CheckboxProps {
  // Names the checkbox, also when it is hidden.
  label: string;
  // Names the checkbox for assistive technology only, where the row around
  // it says what it is for.
  hideLabel?: boolean;
  isSelected: boolean;
  onChange: (isSelected: boolean) => void;
  isDisabled?: boolean;
  name?: string;
}

// A controlled checkbox: a 20 px box, filled with ink and a check when
// selected, inside a tap target at least 44 px tall.
export default function Checkbox({
  label,
  hideLabel = false,
  isSelected,
  onChange,
  isDisabled = false,
  name,
}: CheckboxProps) {
  return (
    <AriaCheckbox
      className="ui-checkbox"
      isSelected={isSelected}
      onChange={onChange}
      isDisabled={isDisabled}
      {...(name === undefined ? {} : { name })}
      {...(hideLabel ? { 'aria-label': label } : {})}
    >
      <span className="ui-checkbox__box" aria-hidden="true">
        {isSelected && <Icon name="check" size={14} />}
      </span>
      {!hideLabel && <span className="ui-checkbox__label body">{label}</span>}
    </AriaCheckbox>
  );
}
