import React from 'react';

import { styled } from '@mui/material/styles';

import Copyright from './Copyright';

const FooterRoot = styled('footer')(({ theme }) => ({
  padding: theme.spacing(3, 2),
  marginTop: 'auto',
  backgroundColor:
    theme.palette.mode === 'light'
      ? theme.palette.grey[200]
      : theme.palette.grey[800],
}));

const Footer: React.FC = () => {
  return (
    <FooterRoot>
      <Copyright />
    </FooterRoot>
  );
};

export default Footer;
