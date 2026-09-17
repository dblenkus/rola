import React from 'react';

import { WithTranslation, withTranslation } from 'react-i18next';

import { withStyles, WithStyles } from '@material-ui/core/styles';

import { Card, CardContent, CardHeader, Grid } from '@material-ui/core';

import InputField from '../InputField';

import { uploadFormStyles } from '../../../styles/general';
import { AuthorModel, DateChange, InputChange } from '../../../types/models';
import DatePicker from '../DatePicker';
import AutocompleteField from '../AutocompleteInput';

interface AuthorFieldProps extends WithStyles<typeof uploadFormStyles>, WithTranslation {
    author: AuthorModel;
    showDob: boolean;
    showClub: boolean;
    requiredClub: boolean;
    showSchool: boolean;
    requiredSchool: boolean;
    handleAUthorChange: (payload: InputChange | DateChange) => void;
}

// eslint-disable-next-line react/prefer-stateless-function
class AuthorField extends React.Component<AuthorFieldProps> {
    render(): React.ReactNode {
        const {
            classes,
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
            <Card className={classes.themeCard} raised>
                <CardHeader
                    title={t('author')}
                    titleTypographyProps={{ align: 'center', variant: 'h3' }}
                />
                <CardContent>
                    <Grid container justify="center" spacing={2}>
                        <Grid item xs={12} sm={6} md={4}>
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
                    <Grid container justify="center" spacing={2}>
                        <Grid item xs={12} sm={6} md={4}>
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
                        <Grid container justify="center" spacing={2}>
                            <Grid item xs={12} sm={6} md={4}>
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
                        <Grid container justify="center" spacing={2}>
                            <Grid item xs={12} sm={6} md={4}>
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
                        <Grid container justify="center" spacing={2}>
                            <Grid item xs={12} sm={6} md={4}>
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
                        <Grid container justify="center" spacing={2}>
                            <Grid item xs={12} sm={6} md={4}>
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
                        <Grid container justify="center" spacing={2}>
                            <Grid item xs={12} sm={6} md={4}>
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

export default withTranslation()(withStyles(uploadFormStyles)(AuthorField));
