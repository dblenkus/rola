import type { SxProps, Theme } from '@mui/material/styles';

export const authSx = {
  alert: { mt: 2 },
  paragraph: { mt: 2 },
  submit: { my: 2, p: 1 },
} satisfies Record<string, SxProps<Theme>>;

export const tableButtonSx: SxProps<Theme> = { p: 0 };

export const formCardSx: SxProps<Theme> = { my: 4 };
