import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import Button from '../../../shared/ui/Button';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import SanitizedHtml from '../../../shared/ui/SanitizedHtml';
import { requestError } from '../../../shared/api/errors';
import { Contest } from '../../../shared/api/types';

import { getContest } from '../../contests';
import './UploadConfirm.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

const UploadConfirmView: React.FC = () => {
  const { t } = useTranslation();
  const [contest, setContest] = useState<Contest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { contestId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }

  useEffect((): void => {
    const fetchContest = async (): Promise<void> => {
      const { data } = await getContest(contestId);
      setContest(data);
    };
    fetchContest().catch((error: unknown) => setError(requestError(error)));
  }, [contestId]);

  return (
    <Page title={t('upload_thanks')}>
      {error ? (
        <Message severity="error">{error}</Message>
      ) : contest ? (
        <SanitizedHtml html={contest.confirmation_html ?? ''} />
      ) : (
        <LoadingProgress />
      )}
      <div className="upload-confirm__back">
        <Button to="/contests">{t('upload_back_to_contests')}</Button>
      </div>
    </Page>
  );
};

export default UploadConfirmView;
