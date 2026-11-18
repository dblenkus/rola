import React, { ReactNode } from 'react';

import Autocomplete from '@mui/material/Autocomplete';
import { CircularProgress, TextField } from '@mui/material';

import { InputChange } from '../models';
import InstitutionService from '../api/InstitutionService';

export interface AutocompleteFieldProps {
  name: string;
  label: string;
  value: string;
  error: string | null;
  required: boolean;
  autoFocus?: boolean;
  onChange: (event: InputChange) => void;
}

const AutocompleteField: React.FC<AutocompleteFieldProps> = ({
  name,
  label,
  value,
  required,
  error,
  autoFocus,
  onChange,
}: AutocompleteFieldProps) => {
  const [open, setOpen] = React.useState(false);
  // Names, so a kept value shows before the list is loaded.
  const [options, setOptions] = React.useState<string[] | null>(null);
  const [failed, setFailed] = React.useState(false);
  const loading = open && options === null && !failed;

  const handleChange = (
    event: React.SyntheticEvent,
    institution: string | null,
  ): void => {
    onChange({ name, value: institution ?? '' });
  };

  React.useEffect(() => {
    let active = true;

    if (!loading) return undefined;

    InstitutionService.getInstitutions()
      .then(({ data }) => {
        if (active) setOptions(data.results.map(({ name }) => name));
      })
      .catch(() => {
        if (active) setFailed(true);
      });

    return (): void => {
      active = false;
    };
  }, [loading]);

  return (
    <Autocomplete<string>
      value={value || null}
      open={open}
      onOpen={(): void => {
        setFailed(false);
        setOpen(true);
      }}
      onClose={(): void => {
        setOpen(false);
      }}
      options={options ?? []}
      loading={loading}
      onChange={handleChange}
      renderInput={(params): ReactNode => (
        <TextField
          {...params}
          name={name}
          variant="outlined"
          margin="normal"
          fullWidth
          label={label}
          required={required}
          autoFocus={autoFocus}
          error={error !== null || failed}
          helperText={error || (failed ? 'Could not load institutions.' : '')}
          slotProps={{
            ...params.slotProps,
            input: {
              ...params.slotProps.input,
              endAdornment: (
                <>
                  {loading && <CircularProgress color="inherit" size={20} />}
                  {params.slotProps.input.endAdornment}
                </>
              ),
            },
          }}
        />
      )}
    />
  );
};

export default AutocompleteField;
