import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from 'react-router';

import { requestError } from '../../../shared/api/errors';
import { Contest, Submission, SubmissionSet } from '../../../shared/api/types';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import { getContest } from '../../contests';
import { getSubmissionSet } from '../api';
import './SubmissionSetView.css';

interface RouteMatchParams {
  contestId: string;
  submissionSetId: string;
}

interface Loaded {
  contest: Contest;
  submissionSet: SubmissionSet;
}

const SubmissionSetView: React.FC = () => {
  const { t } = useTranslation();
  const { contestId, submissionSetId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!submissionSetId) {
    throw new Error('Missing submissionSetId route parameter');
  }
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<Loaded | null>(null);

  useEffect(() => {
    let active = true;
    const fetch = async (): Promise<Loaded> => {
      const { data: contest } = await getContest(contestId);
      const { data: submissionSet } = await getSubmissionSet(submissionSetId);
      return { contest, submissionSet };
    };
    fetch()
      .then((data) => {
        if (active) setLoaded(data);
      })
      .catch((error: unknown) => {
        if (active) setError(requestError(error));
      });
    return () => {
      active = false;
    };
  }, [contestId, submissionSetId]);

  if (error) {
    // The author is not known, so the page is named generically.
    return (
      <Page title={t('admin_submission')} titleHidden>
        <Message severity="error">{error}</Message>
      </Page>
    );
  }
  if (!loaded) {
    return (
      <Page title={t('admin_submission')} titleHidden>
        <LoadingProgress />
      </Page>
    );
  }

  const { contest, submissionSet } = loaded;
  const { author } = submissionSet;
  const authorName = `${author.first_name} ${author.last_name}`;

  const photoAlt = (submission: Submission, index: number): string => {
    const title = submission.title || t('admin_untitled_photograph');
    // The photographs of a series link to different files, so each link
    // needs its own name.
    return submission.files.length > 1
      ? t('admin_series_photo', {
          title,
          number: index + 1,
          count: submission.files.length,
        })
      : title;
  };

  return (
    <Page title={authorName}>
      <dl className="admin-details">
        <div className="admin-details__item">
          <dt className="small">{t('contest')}</dt>
          <dd className="body">{contest.title}</dd>
        </div>
        <div className="admin-details__item">
          <dt className="small">{t('author')}</dt>
          <dd className="body">{authorName}</dd>
        </div>
        {author.email !== null && (
          <div className="admin-details__item">
            <dt className="small">{t('email')}</dt>
            <dd className="body">{author.email}</dd>
          </div>
        )}
      </dl>
      <ul className="admin-photos">
        {submissionSet.submissions.map((submission) => {
          const theme = contest.themes.find(
            ({ id }) => id === submission.theme,
          );
          return (
            <li key={submission.id} className="admin-photos__item">
              <figure className="admin-photo">
                {submission.files.map((file, index) => (
                  <a
                    key={file.id}
                    className="admin-photo__link"
                    href={file.file}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <img
                      className="admin-photo__img"
                      src={file.thumbnail || file.file}
                      alt={photoAlt(submission, index)}
                      loading="lazy"
                      decoding="async"
                    />
                  </a>
                ))}
                <figcaption>
                  <dl className="admin-photo__details">
                    <div className="admin-details__item">
                      <dt className="small">{t('title')}</dt>
                      <dd className="body">
                        {submission.title || t('admin_untitled_photograph')}
                      </dd>
                    </div>
                    <div className="admin-details__item">
                      <dt className="small">{t('theme')}</dt>
                      <dd className="body">{theme?.title}</dd>
                    </div>
                    {submission.description && (
                      <div className="admin-details__item">
                        <dt className="small">{t('description')}</dt>
                        <dd className="body">{submission.description}</dd>
                      </div>
                    )}
                  </dl>
                </figcaption>
              </figure>
            </li>
          );
        })}
      </ul>
    </Page>
  );
};

export default SubmissionSetView;
