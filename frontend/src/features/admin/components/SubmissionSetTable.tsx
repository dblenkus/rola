import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

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

import { Payment, SubmissionSet } from '../../../shared/api/types';
import SubmissionSetTableRow from './SubmissionSetTableRow';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import usePagination from '../../../shared/api/usePagination';
import { requestError } from '../../../shared/api/errors';
import {
  getPaymentsBySubmissionSets,
  getSubmissionSetsByContest,
  updatePayment,
} from '../api';

interface SubmissionSetTableProps {
  contestId: number;
  reloadKey: number;
  onDelete: (submissionSet: SubmissionSet) => void;
}

interface LoadedPayments {
  sets: SubmissionSet[];
  results: Payment[];
}

const SubmissionSetTable: React.FC<SubmissionSetTableProps> = ({
  contestId,
  reloadKey,
  onDelete,
}: SubmissionSetTableProps) => {
  const [error, setError] = useState<string | null>(null);
  // A failed payment update keeps the table so the admin can try again.
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [payments, setPayments] = useState<LoadedPayments>({
    sets: [],
    results: [],
  });
  const source = useCallback(
    (page: number, pageSize: number) =>
      getSubmissionSetsByContest(contestId.toString(), page, pageSize),
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

  const fetchPayments = useCallback(async (): Promise<LoadedPayments> => {
    if (submissionSets.length === 0)
      return { sets: submissionSets, results: [] };

    const submissionSetIds = submissionSets.map(({ id }) => id);
    const { data } = await getPaymentsBySubmissionSets(submissionSetIds);
    return { sets: submissionSets, results: data.results };
  }, [submissionSets]);

  useEffect(() => {
    // A request for rows the table no longer shows must not replace them.
    let active = true;
    fetchPayments()
      .then((loaded) => {
        if (!active) return;
        setPayments(loaded);
        setError(null);
      })
      .catch((error: unknown) => {
        if (active) setError(requestError(error));
      });
    return () => {
      active = false;
    };
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
      await updatePayment(submissionSetId, paid);
      const loaded = await fetchPayments();
      // The admin may have moved to another page while this was saved.
      setPayments((current) =>
        current.sets === loaded.sets ? loaded : current,
      );
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

  const shownPayments =
    payments.sets === submissionSets ? payments.results : [];

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
              const payment = shownPayments.find(
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
