import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';

import { Alert, Grid, Typography } from '@mui/material';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import { requestError } from '../../../shared/api/errors';
import { ResultsSubmission } from '../../../shared/api/types';
import { getResultsOverview } from '../../results';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const ThemeOverview: React.FC = () => {
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

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!submissions) return <LoadingProgress />;
  // The overview uses the public results, which list nothing until the
  // contest's results are published.
  if (!submissions.length)
    return <Typography>No published results.</Typography>;

  return (
    <Grid container>
      {submissions.map((submission) => {
        return (
          <Grid key={submission.id} size={{ xs: 12 }}>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {(submission.files ?? []).map((file) => (
                <img
                  key={file.id}
                  style={{ maxWidth: '30%', margin: '5px' }}
                  src={file.file}
                  alt={submission.title ?? ''}
                  onClick={() => window.open(file.file)}
                />
              ))}
            </div>
            <Typography align="center">
              <b>{submission.title}</b>
              <br />
              {submission.description && (
                <>
                  {submission.description}
                  <br />
                </>
              )}
              Points: {submission.rating}, Author: {submission.author.id},
              Submission id: {submission.id}
              <br />
              <br />
            </Typography>
          </Grid>
        );
      })}
    </Grid>
  );
};

export default ThemeOverview;
