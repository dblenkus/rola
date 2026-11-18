import React from 'react';

import { useTranslation } from 'react-i18next';

import { Box, IconButton } from '@mui/material';
import type { SxProps, Theme } from '@mui/material/styles';
import { Close, NavigateBefore, NavigateNext } from '@mui/icons-material';

import { JurySubmission } from '../../shared/api/types';
import Rating from './Rating';

interface SubmissionRaterProps {
  submission: JurySubmission;
  rating: number;
  ratingDisabled: boolean;
  isSeries: boolean;
  isPrevious: boolean;
  isNext: boolean;
  close: () => void;
  previousSubmission: () => void;
  nextSubmission: () => void;
  updateRating: (value: number) => void;
  onImageError: () => void;
  onImageLoad: () => void;
}

const SubmissionRater: React.FC<SubmissionRaterProps> = ({
  submission,
  rating,
  ratingDisabled,
  isSeries,
  isPrevious,
  isNext,
  close,
  previousSubmission,
  nextSubmission,
  updateRating,
  onImageError,
  onImageLoad,
}: SubmissionRaterProps) => {
  const sx = {
    mainFlex: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    },
    imageFlex: {
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
    },
    image: {
      maxWidth: isSeries ? '30%' : '100%',
      margin: isSeries ? '5px' : '0',
      maxHeight: isSeries ? '40vh' : '80vh',
      flexShrink: 1,
    },
    iconsFlex: {
      alignSelf: 'stretch',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
    },
    invisibleIcon: { visibility: 'hidden' },
    textFlex: {
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    },
  } satisfies Record<string, SxProps<Theme>>;

  const { t } = useTranslation();
  const { description, files, title } = submission;

  return (
    <Box sx={sx.mainFlex}>
      <Box sx={sx.imageFlex}>
        <IconButton disabled={!isPrevious} onClick={() => previousSubmission()}>
          <NavigateBefore />
        </IconButton>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          {files.map((file) => (
            <Box
              key={file.id}
              component="img"
              sx={sx.image}
              src={file.file}
              alt={title ?? ''}
              onError={() => onImageError()}
              onLoad={() => onImageLoad()}
            />
          ))}
        </div>
        <Box sx={sx.iconsFlex}>
          <IconButton onClick={() => close()}>
            <Close />
          </IconButton>
          <IconButton disabled={!isNext} onClick={() => nextSubmission()}>
            <NavigateNext />
          </IconButton>
          {/* Placeholder to match the alignment. */}
          <IconButton sx={sx.invisibleIcon}>
            <Close />
          </IconButton>
        </Box>
      </Box>

      <Box sx={sx.textFlex}>
        <div>
          <b>{t('title')}:</b> {title}
        </div>
        <b>{t('description')}:</b>
        {description}
      </Box>
      <div>
        <Rating
          max={10}
          value={rating}
          disabled={ratingDisabled}
          onChange={(value) => updateRating(value)}
        />
      </div>
    </Box>
  );
};

export default SubmissionRater;
