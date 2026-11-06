import React from 'react';

import { useTranslation } from 'react-i18next';

import { styled } from '@mui/material/styles';

export interface ImageButtonsProps {
  handleChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
  imageRef: React.RefObject<HTMLInputElement | null>;
}

const FileInput = styled('input')({ display: 'none' });

const ImageButtons: React.FC<ImageButtonsProps> = (props) => {
  const { handleChange, imageRef } = props;
  const { t } = useTranslation();

  return (
    <FileInput
      type="file"
      aria-label={t('select_photo')}
      accept="image/jpeg"
      onChange={handleChange}
      ref={imageRef}
    />
  );
};

export default ImageButtons;
