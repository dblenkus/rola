import { useEffect, useState } from 'react';
import { useParams } from 'react-router';

import { Alert, Typography } from '@mui/material';

import ContestService from '../services/ContestService';
import { reportUnexpected } from '../services/errors';
import type { Contest } from '../types/api';

import HeaderImage from '../components/Layout/HeaderImage';
import LoadingProgress from '../components/LoadingProgress';
import NoticeHtml from '../components/Upload/NoticeHtml';
import UploadButton from '../components/Upload/UploadButton';

export default function ContestDetails() {
  const { contestId } = useParams();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  const [contest, setContest] = useState<Contest | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    setContest(null);
    setFailed(false);
    ContestService.getContest(contestId)
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
      <NoticeHtml notice={contest.notice_html ?? ''} />
      <UploadButton contestId={contest.id} />
    </>
  );
}
