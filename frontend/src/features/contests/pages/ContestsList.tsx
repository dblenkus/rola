import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Alert, Grid, Typography } from '@mui/material';

import ContestCard from '../components/ContestCard';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import { reportUnexpected } from '../../../shared/api/errors';
import type { Contest } from '../../../shared/api/types';
import fetchAll from '../../../shared/api/fetchAll';
import { getActiveContests } from '../api';

export default function ContestsListView() {
  const { t } = useTranslation();
  const [contests, setContests] = useState<Contest[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    fetchAll(getActiveContests)
      .then((data) => {
        if (active) setContests(data);
      })
      .catch((error: unknown) => {
        reportUnexpected(error);
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, []);

  if (failed) {
    return <Alert severity="error">{t('could_not_load_contests')}</Alert>;
  }
  if (!contests) return <LoadingProgress />;
  if (!contests.length)
    return <Typography>{t('no_active_contests')}</Typography>;

  return (
    <Grid container spacing={2}>
      {contests.map((contest) => (
        <Grid key={contest.id} size={{ xs: 12, sm: 6, md: 4 }}>
          <ContestCard contest={contest} />
        </Grid>
      ))}
    </Grid>
  );
}
