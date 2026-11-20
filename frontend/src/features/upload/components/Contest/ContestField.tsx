import React, { useId } from 'react';

import { useTranslation } from 'react-i18next';

import Button, { ButtonBar } from '../../../../shared/ui/Button';
import Message from '../../../../shared/ui/Message';
import type { InputChange } from '../../../../shared/ui/TextField';

import { useDeadline } from '../../../contests';
import { ContestModel, DateChange } from '../../models';

import AuthorField from '../Author/AuthorField';
import ContestHead from '../ContestHead/ContestHead';
import ThemeField from '../Theme/ThemeField';
import './ContestField.css';

interface ContestFieldProps {
  contestId: number;
  contest: ContestModel;
  handleAuthorChange: (payload: InputChange | DateChange) => void;
  handleSubmissionChange: (
    theme_id: number,
    submission_id: number,
    payload: InputChange,
  ) => void;
  handleImageChange: (
    theme_id: number,
    submission_id: number,
    image_id: number,
    payload: { file: File | undefined },
  ) => void;
  handleSubmit: () => void;
  uploading: boolean;
}

// The upload form: the contest's header, the entrant's details, a section per
// theme, and the sticky bar with the upload action.
const ContestField: React.FC<ContestFieldProps> = ({
  contestId,
  contest,
  handleAuthorChange,
  handleSubmissionChange,
  handleImageChange,
  handleSubmit,
  uploading,
}) => {
  const { t } = useTranslation();
  const progressId = useId();
  const deadline = useDeadline(contest.meta.endDate);

  const handleClick = (event: React.FormEvent): void => {
    event.preventDefault();
    handleSubmit();
  };

  return (
    <div className="upload-page">
      <ContestHead
        contestId={contestId}
        title={contest.meta.title}
        endDate={contest.meta.endDate}
      />
      {contest.meta.description && (
        <p className="upload-page__description body">
          {contest.meta.description}
        </p>
      )}
      <form className="upload-form" onSubmit={handleClick} noValidate>
        <AuthorField
          handleAUthorChange={handleAuthorChange}
          author={contest.author}
          showDateOfBirth={contest.meta.dateOfBirthRequired}
          showClub={contest.meta.clubVisible}
          requiredClub={contest.meta.clubRequired}
          showSchool={contest.meta.schoolVisible}
          requiredSchool={contest.meta.schoolRequired}
        />

        {contest.themes.map((theme) => (
          <ThemeField
            key={theme.meta.id}
            theme={theme}
            handleSubmissionChange={(submission_id, payload) =>
              handleSubmissionChange(theme.meta.id, submission_id, payload)
            }
            handleImageChange={(submission_id, image_id, payload) =>
              handleImageChange(theme.meta.id, submission_id, image_id, payload)
            }
          />
        ))}
        {contest.errors.hasError && (
          <div className="upload-form__message">
            <Message severity="error">{t('fix_errors')}</Message>
          </div>
        )}
        <ButtonBar
          // Editing is not available yet; deleting is, until entries close.
          note={
            deadline.remaining !== null &&
            t('upload_bar_note', { date: deadline.date })
          }
        >
          {uploading ? (
            // The upload reports no progress, only that it runs, so this
            // says so in words, without a bar.
            <div
              className="upload-form__progress"
              role="progressbar"
              aria-labelledby={progressId}
            >
              <span id={progressId} className="body">
                {t('upload_uploading')}
              </span>
            </div>
          ) : (
            <Button type="submit" variant="primary" size="large" block>
              {t('upload')}
            </Button>
          )}
        </ButtonBar>
      </form>
    </div>
  );
};

export default ContestField;
