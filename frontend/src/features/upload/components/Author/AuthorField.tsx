import React from 'react';

import { useTranslation } from 'react-i18next';

import DateField from '../../../../shared/ui/DateField';
import TextField, { type InputChange } from '../../../../shared/ui/TextField';

import { AuthorModel, DateChange } from '../../models';
import AutocompleteField from '../AutocompleteInput';

interface AuthorFieldProps {
  author: AuthorModel;
  showDob: boolean;
  showClub: boolean;
  requiredClub: boolean;
  showSchool: boolean;
  requiredSchool: boolean;
  handleAUthorChange: (payload: InputChange | DateChange) => void;
}

// The entrant's details, one field under another.
const AuthorField: React.FC<AuthorFieldProps> = ({
  author,
  showDob,
  showClub,
  requiredClub,
  showSchool,
  requiredSchool,
  handleAUthorChange,
}) => {
  const { t } = useTranslation();

  return (
    <section className="upload-author">
      <div className="upload-section-head">
        <h2 className="upload-section-head__title h2-mobile">{t('author')}</h2>
      </div>
      <div className="upload-author__fields">
        <TextField
          name="first_name"
          value={author.first_name}
          error={author.errors.first_name}
          label={t('first_name')}
          autoComplete="given-name"
          autoFocus
          required
          onChange={handleAUthorChange}
        />
        <TextField
          name="last_name"
          value={author.last_name}
          error={author.errors.last_name}
          label={t('last_name')}
          autoComplete="family-name"
          required
          onChange={handleAUthorChange}
        />
        {showDob && (
          <DateField
            name="dob"
            label={t('date_of_birth')}
            value={author.dob}
            error={author.errors.dob}
            required
            autoComplete="bday"
            onChange={handleAUthorChange}
          />
        )}
        {showSchool && (
          <AutocompleteField
            name="school"
            label={t('school')}
            value={author.school ?? ''}
            error={author.errors.school}
            required={requiredSchool}
            onChange={handleAUthorChange}
          />
        )}
        {showSchool && (
          <TextField
            name="mentor"
            value={author.mentor ?? ''}
            error={author.errors.mentor}
            label={t('mentor')}
            onChange={handleAUthorChange}
          />
        )}
        {showClub && (
          <TextField
            name="club"
            value={author.club ?? ''}
            error={author.errors.club}
            label={t('photo_club')}
            required={requiredClub}
            onChange={handleAUthorChange}
          />
        )}
        {showClub && (
          <TextField
            name="distinction"
            value={author.distinction}
            error={author.errors.distinction}
            label={t('photo_distinction')}
            onChange={handleAUthorChange}
          />
        )}
      </div>
    </section>
  );
};

export default AuthorField;
