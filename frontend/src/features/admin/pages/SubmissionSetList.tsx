import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from 'react-router';

import { requestError } from '../../../shared/api/errors';
import { Contest, SubmissionSet } from '../../../shared/api/types';
import ConfirmDialog from '../../../shared/ui/ConfirmDialog';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import { getContest } from '../../contests';
import SubmissionSetTable from '../components/SubmissionSetTable';
import { deleteSubmissionSet } from '../api';

interface RouteMatchParams {
  contestId: string;
}

const SubmissionSetList: React.FC = () => {
  const { t } = useTranslation();
  const { contestId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  const [error, setError] = useState<string | null>(null);
  // A failed delete keeps the table so the admin can try again.
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [contest, setContest] = useState<Contest | null>(null);
  const [pendingSubmissionSet, setPendingSubmissionSet] =
    useState<SubmissionSet | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let active = true;
    getContest(contestId)
      .then(({ data }) => {
        if (active) setContest(data);
      })
      .catch((error: unknown) => {
        if (active) setError(requestError(error));
      });
    return () => {
      active = false;
    };
  }, [contestId]);

  const closeDialog = (): void => setPendingSubmissionSet(null);

  const processDelete = async (): Promise<void> => {
    if (!pendingSubmissionSet) return;

    setDeleteError(null);
    try {
      await deleteSubmissionSet(pendingSubmissionSet.id);
      setReloadKey((key) => key + 1);
    } catch (error) {
      setDeleteError(requestError(error));
    }
  };

  if (error || !contest) {
    // Until the contest is known, the page is named generically.
    return (
      <Page title={t('admin_submissions')} titleHidden>
        {error ? (
          <Message severity="error">{error}</Message>
        ) : (
          <LoadingProgress />
        )}
      </Page>
    );
  }

  return (
    <Page title={contest.title}>
      {deleteError && <Message severity="error">{deleteError}</Message>}
      <SubmissionSetTable
        contestId={contest.id}
        reloadKey={reloadKey}
        onDelete={setPendingSubmissionSet}
      />

      <ConfirmDialog
        open={pendingSubmissionSet !== null}
        title={t('delete_confirmation_title')}
        onClose={closeDialog}
        onConfirm={processDelete}
      >
        {t('delete_confirmation')}
      </ConfirmDialog>
    </Page>
  );
};

export default SubmissionSetList;
