import React from 'react';

import { useTranslation } from 'react-i18next';

import { SubmissionModel, InputChange } from '../../../types/models';

import InputField from '../InputField';

export interface DescriptionFieldProps {
  submission: SubmissionModel;
  onChange: (payload: InputChange) => void;
}

const DescriptionField: React.FC<DescriptionFieldProps> = (props) => {
  const { t } = useTranslation();
  const { submission, onChange } = props;

  return (
    <InputField
      sx={{ my: 1 }}
      name="description"
      value={submission.description}
      error={submission.errors.description}
      label={t('description')}
      autoComplete=""
      required={submission.meta.descriptionRequired}
      rows={3}
      onChange={onChange}
    />
  );
};

export default DescriptionField;
