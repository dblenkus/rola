import React from 'react';

import { WithTranslation, withTranslation } from 'react-i18next';

import { Card, CardContent, CardHeader, Grid } from '@mui/material';

import InputField from '../InputField';

import { formCardSx } from '../../../../shared/ui/styles';
import { AuthorModel, DateChange, InputChange } from '../../models';
import DatePicker from '../DatePicker';
import AutocompleteField from '../AutocompleteInput';

interface AuthorFieldProps extends WithTranslation {
  author: AuthorModel;
  showDob: boolean;
  showClub: boolean;
  requiredClub: boolean;
  showSchool: boolean;
  requiredSchool: boolean;
  handleAUthorChange: (payload: InputChange | DateChange) => void;
}

class AuthorField extends React.Component<AuthorFieldProps> {
  render(): React.ReactNode {
    const {
      author,
      showDob,
      showClub,
      requiredClub,
      showSchool,
      requiredSchool,
      handleAUthorChange,
      t,
    } = this.props;

    return (
      <Card sx={formCardSx} raised>
        <CardHeader
          title={t('author')}
          slotProps={{
            title: { component: 'h3', align: 'center', variant: 'h3' },
          }}
        />
        <CardContent>
          <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
            <Grid size={{ xs: 12, sm: 6, md: 4 }}>
              <InputField
                name="first_name"
                value={author.first_name}
                error={author.errors.first_name}
                label={t('first_name')}
                autoComplete="given-name"
                autoFocus
                required
                onChange={handleAUthorChange}
              />
            </Grid>
          </Grid>
          <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
            <Grid size={{ xs: 12, sm: 6, md: 4 }}>
              <InputField
                name="last_name"
                value={author.last_name}
                error={author.errors.last_name}
                label={t('last_name')}
                autoComplete="family-name"
                required
                onChange={handleAUthorChange}
              />
            </Grid>
          </Grid>
          {showDob && (
            <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <DatePicker
                  name="dob"
                  label={t('date_of_birth')}
                  value={author.dob || null}
                  error={author.errors.dob}
                  required
                  autoComplete="bday"
                  onChange={handleAUthorChange}
                />
              </Grid>
            </Grid>
          )}
          {showSchool && (
            <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <AutocompleteField
                  name="school"
                  label={t('school')}
                  value={author.school || ''}
                  error={author.errors.school}
                  required={requiredSchool}
                  onChange={handleAUthorChange}
                />
              </Grid>
            </Grid>
          )}
          {showSchool && (
            <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <InputField
                  name="mentor"
                  value={author.mentor}
                  error={author.errors.mentor}
                  label={t('mentor')}
                  autoComplete=""
                  onChange={handleAUthorChange}
                />
              </Grid>
            </Grid>
          )}
          {showClub && (
            <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <InputField
                  name="club"
                  value={author.club}
                  error={author.errors.club}
                  label={t('photo_club')}
                  required={requiredClub}
                  autoComplete=""
                  onChange={handleAUthorChange}
                />
              </Grid>
            </Grid>
          )}
          {showClub && (
            <Grid container spacing={2} sx={{ justifyContent: 'center' }}>
              <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                <InputField
                  name="distinction"
                  value={author.distinction}
                  error={author.errors.distinction}
                  label={t('photo_distinction')}
                  autoComplete=""
                  onChange={handleAUthorChange}
                />
              </Grid>
            </Grid>
          )}
        </CardContent>
      </Card>
    );
  }
}

export default withTranslation()(AuthorField);
