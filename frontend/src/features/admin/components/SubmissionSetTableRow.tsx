import React from 'react';
import { Link } from 'react-router';

import { useTranslation } from 'react-i18next';

import { Button, Checkbox, TableCell, TableRow } from '@mui/material';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import MoneyOffIcon from '@mui/icons-material/MoneyOff';

import { tableButtonSx } from '../../../shared/ui/styles';
import { Payment, SubmissionSet } from '../../../shared/api/types';

interface SubmissionSetTableRowProps {
  contestId: number;
  submissionSet: SubmissionSet;
  payment: Payment | undefined;
  onPaidChange: (submissionSetId: number, paid: boolean) => void;
  onDelete: (submissionSet: SubmissionSet) => void;
}

const getSubmissionSetAuthor = (submissionSet: SubmissionSet): string => {
  const { first_name: firstName, last_name: lastName } = submissionSet.author;
  return `${firstName} ${lastName}`;
};

const getViewLink = (
  contestId: number,
  submissionSet: SubmissionSet,
): string => {
  return `/admin/contest/${contestId}/submission/${submissionSet.id}`;
};

const SubmissionSetTableRow: React.FC<SubmissionSetTableRowProps> = ({
  contestId,
  submissionSet,
  payment,
  onPaidChange,
  onDelete,
}: SubmissionSetTableRowProps) => {
  const { t } = useTranslation();

  const handlePaidChange = (
    event: React.ChangeEvent<HTMLInputElement>,
  ): void => {
    onPaidChange(submissionSet.id, event.target.checked);
  };

  const themeNumber = new Set(
    submissionSet.submissions.map(({ theme }) => theme),
  ).size;

  return (
    <TableRow>
      <TableCell component="th" scope="row">
        {getSubmissionSetAuthor(submissionSet)}
      </TableCell>
      <TableCell>{new Date(submissionSet.created).toLocaleString()}</TableCell>
      <TableCell>{themeNumber}</TableCell>
      <TableCell>{submissionSet.submissions.length}</TableCell>
      <TableCell>
        <Checkbox
          checked={!!payment && payment.paid}
          icon={<MoneyOffIcon color="secondary" />}
          checkedIcon={<AttachMoneyIcon color="primary" />}
          onChange={handlePaidChange}
        />
      </TableCell>
      <TableCell align="right">
        <Button
          component={Link}
          to={getViewLink(contestId, submissionSet)}
          sx={tableButtonSx}
          color="primary"
        >
          {t('view')}
        </Button>
        <Button
          variant="text"
          sx={tableButtonSx}
          color="secondary"
          onClick={(): void => {
            onDelete(submissionSet);
          }}
        >
          {t('delete')}
        </Button>
      </TableCell>
    </TableRow>
  );
};

export default SubmissionSetTableRow;
