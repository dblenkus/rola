import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import ContestRow from '../components/ContestRow';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import { reportUnexpected } from '../../../shared/api/errors';
import type { Contest } from '../../../shared/api/types';
import fetchAll from '../../../shared/api/fetchAll';
import { getActiveContests } from '../api';
import './ContestsList.css';

export default function ContestsListView() {
  const { t } = useTranslation();
  const [contests, setContests] = useState<Contest[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    fetchAll(getActiveContests)
      .then((data) => {
        if (active) setContests(data);
      })
      .catch((error: unknown) => {
        reportUnexpected(error);
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <Page title={t('active_contests')}>
      <ContestsListContent failed={failed} contests={contests} />
    </Page>
  );
}

function ContestsListContent({
  failed,
  contests,
}: {
  failed: boolean;
  contests: Contest[] | null;
}) {
  const { t } = useTranslation();
  if (failed) {
    return <Message severity="error">{t('could_not_load_contests')}</Message>;
  }
  if (!contests) return <LoadingProgress />;
  if (!contests.length) {
    return <p className="body">{t('no_active_contests')}</p>;
  }
  return (
    <ul className="contests-list">
      {contests.map((contest) => (
        <ContestRow key={contest.id} contest={contest} />
      ))}
    </ul>
  );
}
