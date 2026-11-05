import React from 'react';
import { Box, Card, Grid } from '@mui/material';
import type { SxProps, Theme } from '@mui/material/styles';

import { Rating as RatingModel, Submission } from '../../types/api';
import Rating from './Rating';

interface ThemeGalleryProps {
  submissions: Submission[];
  isSeries: boolean;
  ratings: RatingModel[];
  handleClick: (submissionId: number) => void;
}

const ThemeGallery: React.FC<ThemeGalleryProps> = ({
  submissions,
  isSeries,
  ratings,
  handleClick,
}: ThemeGalleryProps) => {
  const sx = {
    card: { cursor: 'pointer' },
    wrapOut: {
      width: '100%',
      paddingBottom: isSeries ? '10%' : '100%',
      position: 'relative',
    },
    wrapIn: {
      position: 'absolute',
      top: 0,
      bottom: 0,
      left: 0,
      right: 0,
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minWidth: 0,
    },
    image: {
      maxHeight: '100%',
      maxWidth: '100%',
      padding: '5px',
    },
    centered: { textAlign: 'center' },
  } satisfies Record<string, SxProps<Theme>>;

  return (
    <Grid container spacing={2}>
      {submissions.map(({ id, files, title }) => {
        const rating = ratings.find((r) => r.submission === id);
        return isSeries ? (
          <Grid key={id} size={{ xs: 12 }}>
            <Card raised sx={sx.card} onClick={() => handleClick(id)}>
              <Box sx={sx.wrapOut}>
                <Box sx={sx.wrapIn}>
                  {files.map((file) => (
                    <Box
                      component="img"
                      key={file.id}
                      sx={sx.image}
                      src={file.thumbnail || file.file}
                      alt={title ?? ''}
                    />
                  ))}
                </Box>
              </Box>
              <Box sx={sx.centered}>
                <b>{title}</b>
              </Box>
              <Box sx={sx.centered}>
                <Rating
                  max={10}
                  value={rating?.rating || 0}
                  size="small"
                  disabled
                />
              </Box>
            </Card>
          </Grid>
        ) : (
          <Grid key={id} size={{ xs: 6, sm: 4, md: 3, lg: 3 }}>
            <Card raised sx={sx.card} onClick={() => handleClick(id)}>
              <Box sx={sx.wrapOut}>
                <Box sx={sx.wrapIn}>
                  {files.map((file) => (
                    <Box
                      component="img"
                      key={file.id}
                      sx={sx.image}
                      src={file.thumbnail || file.file}
                      alt={title ?? ''}
                    />
                  ))}
                </Box>
              </Box>
              <Box sx={sx.centered}>
                <b>{title}</b>
              </Box>
              <Box sx={sx.centered}>
                <Rating
                  max={10}
                  value={rating?.rating || 0}
                  size="small"
                  disabled
                />
              </Box>
            </Card>
          </Grid>
        );
      })}
    </Grid>
  );
};

export default ThemeGallery;
