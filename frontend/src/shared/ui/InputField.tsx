import React from 'react';

import { TextField } from '@mui/material';
import type { SxProps, Theme } from '@mui/material/styles';

// The change a text field reports: the field's name and its new value.
export interface InputChange {
  name: string;
  value: string;
}

export interface InputFieldProps {
  sx: SxProps<Theme>;
  name: string;
  label: string;
  value: string;
  error: string | null;
  autoComplete: string;
  type: string;
  required: boolean;
  rows: number;
  autoFocus: boolean;
  onChange: (event: InputChange) => void;
}

class InputField extends React.Component<InputFieldProps> {
  static defaultProps = {
    sx: {},
    type: 'text',
    value: '',
    error: null,
    required: false,
    rows: 1,
    autoFocus: false,
  };

  onChange = ({ target }: React.ChangeEvent<HTMLInputElement>): void => {
    const { value } = target;
    const { onChange, name } = this.props;
    onChange({ name, value });
  };

  render(): React.ReactNode {
    const {
      autoComplete,
      autoFocus,
      label,
      name,
      required,
      rows,
      type,
      value,
      error,
      sx,
    } = this.props;

    return (
      <TextField
        sx={sx}
        name={name}
        variant="outlined"
        margin="normal"
        fullWidth
        label={label}
        type={type}
        required={required}
        multiline={rows > 1}
        rows={rows}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        onChange={this.onChange}
        value={value}
        error={error !== null}
        helperText={error || ''}
      />
    );
  }
}

export default InputField;
