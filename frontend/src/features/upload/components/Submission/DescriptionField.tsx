import React from 'react';

import { useTranslation } from 'react-i18next';

import { SubmissionModel } from '../../models';
import TextField, { type InputChange } from '../../../../shared/ui/TextField';

export interface DescriptionFieldProps {
  submission: SubmissionModel;
  onChange: (payload: InputChange) => void;
}

const DescriptionField: React.FC<DescriptionFieldProps> = (props) => {
  const { t } = useTranslation();
  const { submission, onChange } = props;

  return (
    <TextField
      name="description"
      value={submission.description}
      error={submission.errors.description}
      label={t('description')}
      autoComplete="off"
      required={submission.meta.descriptionRequired}
      rows={3}
      onChange={onChange}
    />
  );
};

export default DescriptionField;
