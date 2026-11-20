import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { useTranslation } from 'react-i18next';

import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import Thumbnail from '../../../shared/ui/Thumbnail';
import ThumbnailGrid from '../../../shared/ui/ThumbnailGrid';
import { requestError } from '../../../shared/api/errors';
import { ResultsSubmission } from '../../../shared/api/types';
import { getResultsOverview } from '../../results';
import './ThemeOverview.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const ThemeOverview: React.FC = () => {
  const { t } = useTranslation();
  const { themeId } = useParams<keyof RouteMatchParams>();
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }

  const [submissions, setSubmissions] = useState<null | ResultsSubmission[]>();
  const [error, setError] = useState<string | null>(null);

  // Initialize the state.
  useEffect(() => {
    const fetch = async (): Promise<void> => {
      const { data } = await getResultsOverview(themeId);
      setSubmissions(data.results);
    };
    fetch().catch((error: unknown) => setError(requestError(error)));
  }, [themeId]);

  if (error) return <Message severity="error">{error}</Message>;
  if (!submissions) return <LoadingProgress />;

  return (
    <Page title={t('jury_overview_title')}>
      {/* The overview uses the public results, which list nothing until the
          contest's results are published. */}
      {submissions.length ? (
        <ol className="jury-overview">
          {submissions.map((submission) => (
            <li key={submission.id} className="jury-overview__entry">
              <figure className="jury-overview__figure">
                <ThumbnailGrid layout="page">
                  {(submission.files ?? []).map((file) => (
                    <a
                      key={file.id}
                      className="jury-overview__photo"
                      href={file.file}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <Thumbnail
                        fit="contain"
                        src={file.thumbnail || file.file}
                        alt={submission.title ?? ''}
                      />
                    </a>
                  ))}
                </ThumbnailGrid>
                <figcaption className="jury-overview__caption">
                  <p className="jury-overview__title body">
                    {submission.title}
                  </p>
                  {submission.description && (
                    <p className="jury-overview__description body">
                      {submission.description}
                    </p>
                  )}
                  <p className="jury-overview__details small">
                    {t('overview_details', {
                      points: submission.score,
                      author: submission.author.id,
                      submission: submission.id,
                    })}
                  </p>
                </figcaption>
              </figure>
            </li>
          ))}
        </ol>
      ) : (
        <p className="body jury-overview__empty">{t('no_published_results')}</p>
      )}
    </Page>
  );
};

export default ThemeOverview;
