import { Grid, Typography } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import LoadingProgress from '../components/LoadingProgress';
import ContestService from '../services/ContestService';
import { Contest } from '../types/api';

import ConfirmationHtml from '../components/Upload/ConfirmationHtml';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const UploadConfirmView: React.FC = () => {
  const [contest, setContest] = useState<Contest | null>(null);
  const { contestId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }

  useEffect((): void => {
    const fetchContest = async (): Promise<void> => {
      const { data } = await ContestService.getContest(contestId);
      setContest(data);
    };
    fetchContest();
  }, [contestId]);

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
