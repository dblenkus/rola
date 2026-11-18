import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';

import { Alert, Box, Typography } from '@mui/material';

import LoadingProgress from '../../../shared/ui/LoadingProgress';
import ResultsSubmissionService from '../api/ResultsSubmissionService';
import { requestError } from '../../../shared/api/errors';
import { ResultsSubmission } from '../../../shared/api/types';

interface RouteMatchParams {
  submissionId: string;
}

const SubmissionResults: React.FC = () => {
  const [submission, setSubmission] = useState<null | ResultsSubmission>(null);
  const [error, setError] = useState<string | null>(null);
  const { submissionId } = useParams<keyof RouteMatchParams>();
  if (!submissionId) {
    throw new Error('Missing submissionId route parameter');
  }

  useEffect(() => {
    const fetch = async (): Promise<void> => {
      const { data } = await ResultsSubmissionService.get(submissionId);
      setSubmission(data);
    };
    fetch().catch((error: unknown) => setError(requestError(error)));
  }, [submissionId]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!submission) return <LoadingProgress />;

  const { title, author } = submission;
  const files = submission.files ?? [];

  return (
    <>
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {files.slice(0, 3).map((file) => (
            <img
              key={file.id}
              style={{
                maxWidth: files.length === 1 ? '100%' : '30%',
                maxHeight: files.length === 1 ? '85vh' : '40vh',
                margin: '5px',
              }}
              src={file.file}
              alt={submission.title ?? ''}
            />
          ))}
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {files.slice(3, 6).map((file) => (
            <img
              key={file.id}
              style={{
                maxWidth: '30%',
                maxHeight: '40vh',
                margin: '5px',
              }}
              src={file.file}
              alt={submission.title ?? ''}
            />
          ))}
        </div>
        <Box sx={{ paddingTop: '0.5em' }}>
          <Typography align="center">
            <b>{title}</b>, {author.first_name} {author.last_name} (
            {author.country})
            {submission.reward_label && (
              <>
                <br />
                {submission.reward_label}
              </>
            )}
            {submission.description && (
              <>
                <br />
                {submission.description}
              </>
            )}
          </Typography>
        </Box>
      </Box>
    </>
  );
};

export default SubmissionResults;
