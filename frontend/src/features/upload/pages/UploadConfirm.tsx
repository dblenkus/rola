import { Alert, Grid, Typography } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import ContestService from '../../contests/api/ContestService';
import { requestError } from '../../../shared/api/errors';
import { Contest } from '../../../shared/api/types';

import ConfirmationHtml from '../components/ConfirmationHtml';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const UploadConfirmView: React.FC = () => {
  const [contest, setContest] = useState<Contest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { contestId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }

  useEffect((): void => {
    const fetchContest = async (): Promise<void> => {
      const { data } = await ContestService.getContest(contestId);
      setContest(data);
    };
    fetchContest().catch((error: unknown) => setError(requestError(error)));
  }, [contestId]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!contest) return <LoadingProgress />;

  return (
    <Grid container>
      <Grid size={{ xs: 12 }}>
        <Typography variant="h3" align="center">
          Thank you for uploading photos!
        </Typography>
      </Grid>
      <Grid size={{ xs: 12 }}>
        <ConfirmationHtml html={contest.confirmation_html ?? ''} />
      </Grid>
    </Grid>
  );
};

export default UploadConfirmView;
