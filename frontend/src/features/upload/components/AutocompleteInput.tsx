import React from 'react';
import { useTranslation } from 'react-i18next';

import ComboBoxField from '../../../shared/ui/ComboBoxField';
import type { InputChange } from '../../../shared/ui/TextField';
import { getInstitutions } from '../api';

export interface AutocompleteFieldProps {
  name: string;
  label: string;
  value: string;
  error: string | null;
  required: boolean;
  autoFocus?: boolean;
  onChange: (event: InputChange) => void;
}

// The institution lookup: suggests the names of the known institutions.
const AutocompleteField: React.FC<AutocompleteFieldProps> = ({
  name,
  label,
  value,
  required,
  error,
  autoFocus = false,
  onChange,
}: AutocompleteFieldProps) => {
  const { t } = useTranslation();
  const loadInstitutions = async (): Promise<string[]> => {
    const { data } = await getInstitutions();
    return data.results.map(({ name }) => name);
  };

  return (
    <ComboBoxField
      name={name}
      label={label}
      value={value}
      error={error}
      required={required}
      autoFocus={autoFocus}
      onChange={onChange}
      loadOptions={loadInstitutions}
      loadErrorMessage={t('could_not_load_institutions')}
    />
  );
};

export default AutocompleteField;
