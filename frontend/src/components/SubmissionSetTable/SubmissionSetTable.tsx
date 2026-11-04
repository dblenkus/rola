import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import _ from 'lodash';

import {
  Alert,
  LabelDisplayedRowsArgs,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableFooter,
  TableHead,
  TablePagination,
  TableRow,
} from '@mui/material';

import { Payment, SubmissionSet } from '../../types/api';
import SubmissionSetTableRow from './SubmissionSetTableRow';
import LoadingProgress from '../LoadingProgress';
import usePagination from '../../services/usePagination';
import { requestError } from '../../services/errors';
import PaymentService from '../../services/PaymentService';
import SubmissionSetService from '../../services/SubmissionSetService';

interface SubmissionSetTableProps {
  contestId: number;
  reloadKey: number;
  onDelete: (submissionSet: SubmissionSet) => void;
}

const SubmissionSetTable: React.FC<SubmissionSetTableProps> = ({
  contestId,
  reloadKey,
  onDelete,
}: SubmissionSetTableProps) => {
  const [error, setError] = useState<string | null>(null);
  // A failed payment update keeps the table so the admin can try again.
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [payments, setPayments] = useState<Payment[]>([]);
  const source = useCallback(
    (page: number, pageSize: number) =>
      SubmissionSetService.getByContest(contestId.toString(), page, pageSize),
    [contestId],
  );
  const {
    error: paginationError,
    isLoading,
    data: submissionSets,
    count,
    page,
    pageSize,
    changePage,
    changePageSize,
  } = usePagination<SubmissionSet>({ source, reloadKey });
  const { t } = useTranslation();

  const fetchPayments = useCallback(async (): Promise<void> => {
    if (submissionSets.length === 0) {
      setPayments([]);
      return;
    }

    const submissionSetIds = _.map(submissionSets, 'id');
    const { data } = await PaymentService.getBySubmissionSets(submissionSetIds);
    setPayments(data.results);
  }, [submissionSets]);

  useEffect(() => {
    fetchPayments().catch((error: unknown) => setError(requestError(error)));
  }, [fetchPayments]);

  const handlePageChange = (
    event: React.MouseEvent<HTMLButtonElement> | null,
    newPage: number,
  ): void => {
    changePage(newPage + 1);
  };

  const handleChangeRowsPerPage = (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ): void => {
    changePageSize(parseInt(event.target.value, 10));
  };

  const handlePaidChange = async (
    submissionSetId: number,
    paid: boolean,
  ): Promise<void> => {
    setPaymentError(null);
    try {
      await PaymentService.updatePayment(submissionSetId, paid);
      await fetchPayments();
    } catch (error) {
      setPaymentError(requestError(error));
    }
  };

  const getLabelDisplayedRows = ({
    from,
    to,
    count: total,
  }: LabelDisplayedRowsArgs): React.ReactNode => {
    return t('displayed_rows', { from, to, total });
  };

  if (error || paginationError)
    return <Alert severity="error">{error || paginationError}</Alert>;
  if (isLoading) return <LoadingProgress />;

  return (
    <>
      {paymentError && <Alert severity="error">{paymentError}</Alert>}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('name')}</TableCell>
              <TableCell>{t('submited')}</TableCell>
              <TableCell>{t('n_themes')}</TableCell>
              <TableCell>{t('n_submissions')}</TableCell>
              <TableCell>{t('paid')}</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {submissionSets.map((submissionSet) => {
              const payment = _.find(
                payments,
                (p) => p.submissionset === submissionSet.id,
              );
              return (
                <SubmissionSetTableRow
                  key={submissionSet.id}
                  contestId={contestId}
                  submissionSet={submissionSet}
                  payment={payment}
                  onPaidChange={handlePaidChange}
                  onDelete={onDelete}
                />
              );
            })}
          </TableBody>
          <TableFooter>
            <TableRow>
              <TablePagination
                rowsPerPageOptions={[1, 20, 50, 100]}
                count={count}
                rowsPerPage={pageSize}
                page={page - 1}
                onPageChange={handlePageChange}
                onRowsPerPageChange={handleChangeRowsPerPage}
                labelRowsPerPage={t('rows_per_page')}
                labelDisplayedRows={getLabelDisplayedRows}
              />
            </TableRow>
          </TableFooter>
        </Table>
      </TableContainer>
    </>
  );
};

export default SubmissionSetTable;
