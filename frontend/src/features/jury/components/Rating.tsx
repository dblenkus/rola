import React, { useState } from 'react';

import { Star } from '@mui/icons-material';

interface RatingProps {
  max: number;
  value: number;
  size?: 'small' | 'medium' | 'large';
  disabled?: boolean;
  onChange?: (value: number) => void;
}

const Rating: React.FC<RatingProps> = ({
  max,
  value,
  size = 'medium',
  disabled = false,
  onChange,
}: RatingProps) => {
  const [displayValue, setDisplayValue] = useState<number | null>(null);

  const handleMouseOver = (newValue: number): void => {
    if (!disabled) setDisplayValue(newValue + 1);
  };
  const handleMouseLeave = (): void => {
    if (!disabled) setDisplayValue(null);
  };
  const handleClick = (clickedValue: number): void => {
    if (!disabled && onChange) onChange(clickedValue + 1);
  };

  return (
    <>
      {Array.from({ length: max }, (_, i) => (
        <Star
          key={i}
          fontSize={size}
          sx={{
            cursor: 'pointer',
            color: i < (displayValue || value) ? '#ffb400' : '#bebebe',
          }}
          onMouseOver={() => handleMouseOver(i)}
          onFocus={() => handleMouseOver(i)}
          onMouseLeave={() => handleMouseLeave()}
          onBlur={() => handleMouseLeave()}
          onClick={() => handleClick(i)}
        />
      ))}
    </>
  );
};

export default Rating;
