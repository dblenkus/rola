import React from 'react';
import { useTranslation } from 'react-i18next';

import { Payment, SubmissionSet } from '../../../shared/api/types';
import Button from '../../../shared/ui/Button';
import Checkbox from '../../../shared/ui/Checkbox';
import { formatDateTime, parseApiDate } from '../../../shared/utils/formatDate';
import { TableCell, TableRow } from '../../../shared/ui/Table';
import './SubmissionSetTableRow.css';

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
  const { t, i18n } = useTranslation();
  const language = i18n.resolvedLanguage === 'sl' ? 'sl' : 'en';

  const author = getSubmissionSetAuthor(submissionSet);
  const paid = !!payment && payment.paid === true;
  const themeNumber = new Set(
    submissionSet.submissions.map(({ theme }) => theme),
  ).size;

  return (
    <TableRow>
      <TableCell header label={t('name')}>
        {author}
      </TableCell>
      <TableCell label={t('submited')}>
        {formatDateTime(parseApiDate(submissionSet.created), language)}
      </TableCell>
      <TableCell label={t('n_themes')}>{themeNumber}</TableCell>
      <TableCell label={t('n_submissions')}>
        {submissionSet.submissions.length}
      </TableCell>
      {/* On phones the label says the state in words above the box. */}
      <TableCell label={paid ? t('admin_state_paid') : t('admin_state_unpaid')}>
        <Checkbox
          label={t('admin_paid_checkbox', { name: author })}
          hideLabel
          isSelected={paid}
          onChange={(isSelected) => onPaidChange(submissionSet.id, isSelected)}
        />
      </TableCell>
      <TableCell align="end">
        <span className="admin-row-actions">
          <Button
            variant="quiet"
            size="dense"
            to={getViewLink(contestId, submissionSet)}
          >
            {t('view')}
          </Button>
          <Button
            variant="quiet"
            size="dense"
            onPress={(): void => {
              onDelete(submissionSet);
            }}
          >
            {t('delete')}
          </Button>
        </span>
      </TableCell>
    </TableRow>
  );
};

export default SubmissionSetTableRow;
