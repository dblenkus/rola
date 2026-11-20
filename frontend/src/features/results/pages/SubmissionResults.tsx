import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from 'react-router';

import { requestError } from '../../../shared/api/errors';
import { ResultsSubmission } from '../../../shared/api/types';
import AwardMark from '../../../shared/ui/AwardMark';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import { getResultsSubmission } from '../api';
import './SubmissionResults.css';

interface RouteMatchParams {
  submissionId: string;
}

const SubmissionResults: React.FC = () => {
  const { t } = useTranslation();
  const [submission, setSubmission] = useState<null | ResultsSubmission>(null);
  const [error, setError] = useState<string | null>(null);
  const { submissionId } = useParams<keyof RouteMatchParams>();
  if (!submissionId) {
    throw new Error('Missing submissionId route parameter');
  }

  useEffect(() => {
    const fetch = async (): Promise<void> => {
      const { data } = await getResultsSubmission(submissionId);
      setSubmission(data);
    };
    fetch().catch((error: unknown) => setError(requestError(error)));
  }, [submissionId]);

  if (error) return <Message severity="error">{error}</Message>;
  if (!submission) return <LoadingProgress />;

  const { author } = submission;
  const title = submission.title || t('results_untitled');
  const files = submission.files ?? [];
  const series = files.length > 1;

  // The page's h1 is the title in the wall label under the photo.
  return (
    <Page title={title} ownHeading width="full">
      <div
        className={
          series ? 'results-photos results-photos--series' : 'results-photos'
        }
      >
        {files.map((file, index) => (
          <img
            key={file.id}
            className="results-photo"
            src={file.file}
            alt={
              series
                ? t('results_series_photo', {
                    title,
                    number: index + 1,
                    count: files.length,
                  })
                : title
            }
            loading={index === 0 ? 'eager' : 'lazy'}
            decoding="async"
          />
        ))}
      </div>
      <div className="results-label">
        <h1 className="results-label__title photo-title">{title}</h1>
        <p className="results-label__author body">
          {author.first_name} {author.last_name} ({author.country})
        </p>
        {submission.reward_label && (
          <p className="results-label__award">
            <AwardMark name={submission.reward_label} />
          </p>
        )}
        {submission.description && (
          <p className="results-label__description body">
            {submission.description}
          </p>
        )}
      </div>
    </Page>
  );
};

export default SubmissionResults;
