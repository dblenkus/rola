import { useEffect, useState } from 'react';
import { useParams } from 'react-router';

import { Alert, Typography } from '@mui/material';

import { reportUnexpected } from '../../../shared/api/errors';
import type { Contest } from '../../../shared/api/types';

import HeaderImage from '../../../shared/ui/Layout/HeaderImage';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import SanitizedHtml from '../../../shared/ui/SanitizedHtml';
import UploadButton from '../components/UploadButton';
import { getContest } from '../api';

export default function ContestDetails() {
  const { contestId } = useParams();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  // The key gives each contest its own state, so a route change to another
  // contest starts from loading.
  return <ContestPage key={contestId} contestId={contestId} />;
}

function ContestPage({ contestId }: { contestId: string }) {
  const [contest, setContest] = useState<Contest | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    getContest(contestId)
      .then(({ data }) => {
        if (active) setContest(data);
      })
      .catch((error: unknown) => {
        reportUnexpected(error);
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [contestId]);

  if (failed) {
    return <Alert severity="error">Could not load this contest.</Alert>;
  }
  if (!contest) return <LoadingProgress />;

  return (
    <>
      {contest.header_image ? (
        <HeaderImage src={contest.header_image} />
      ) : (
        <Typography align="center" variant="h2">
          {contest.title}
        </Typography>
      )}
      <UploadButton contestId={contest.id} />
      <SanitizedHtml html={contest.notice_html ?? ''} />
      <UploadButton contestId={contest.id} />
    </>
  );
}
