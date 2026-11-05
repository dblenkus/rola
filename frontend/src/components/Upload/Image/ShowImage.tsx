import React from 'react';

import { Box } from '@mui/material';

export interface ShowImageProps {
  src: string | undefined;
  error: boolean;
}

const ShowImage: React.FC<ShowImageProps> = (props) => {
  const { error, src } = props;

  return (
    <Box
      component="img"
      sx={{
        border: error ? '1px solid #f00' : '1px solid #ddd',
        borderRadius: '4px',
        maxHeight: '100%',
        padding: '5px',
        width: '100%',
      }}
      src={src || '/img/no-photo.png'}
      alt="Missing"
    />
  );
};

export default ShowImage;
