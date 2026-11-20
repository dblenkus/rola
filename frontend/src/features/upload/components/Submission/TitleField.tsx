import React from 'react';

import { useTranslation } from 'react-i18next';

import { SubmissionModel } from '../../models';
import TextField, { type InputChange } from '../../../../shared/ui/TextField';

export interface TitleFieldProps {
  submission: SubmissionModel;
  onChange: (payload: InputChange) => void;
  // The photograph's slot when the field titles one photograph in its row,
  // where the photograph labels it on screen; a series' one title has none.
  slot?: string;
}

const TitleField: React.FC<TitleFieldProps> = (props) => {
  const { submission, onChange, slot } = props;
  const { t } = useTranslation();

  return (
    <TextField
      name="title"
      value={submission.title}
      error={submission.errors.title}
      label={
        slot === undefined ? t('title') : t('upload_photo_title', { slot })
      }
      hideLabel={slot !== undefined}
      // Every photograph has its own title; earlier entries are no help.
      autoComplete="off"
      placeholder={t('upload_title_placeholder')}
      required={submission.meta.titleRequired}
      onChange={onChange}
    />
  );
};

export default TitleField;
