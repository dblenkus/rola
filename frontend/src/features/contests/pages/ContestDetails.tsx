import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { useTranslation } from 'react-i18next';

import { reportUnexpected } from '../../../shared/api/errors';
import type { Contest } from '../../../shared/api/types';

import Icon from '../../../shared/ui/Icon';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import SanitizedHtml from '../../../shared/ui/SanitizedHtml';
import UploadButton from '../components/UploadButton';
import useDeadline from '../hooks/useDeadline';
import { getContest } from '../api';
import './ContestDetails.css';

export default function ContestDetails() {
  const { contestId } = useParams();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  // The key gives each contest its own state, so a route change to another
  // contest starts from loading.
  return <ContestPage key={contestId} contestId={contestId} />;
}

function ContestPage({ contestId }: { contestId: string }) {
  const { t } = useTranslation();
  const [contest, setContest] = useState<Contest | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    getContest(contestId)
      .then(({ data }) => {
        if (active) setContest(data);
      })
      .catch((error: unknown) => {
        reportUnexpected(error);
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [contestId]);

  if (contest) return <ContestView contest={contest} />;
  // Until the contest's title is known, the page is named generically.
  return (
    <Page title={t('contests_contest')} titleHidden>
      {failed ? (
        <Message severity="error">{t('could_not_load_contest')}</Message>
      ) : (
        <LoadingProgress />
      )}
    </Page>
  );
}

function ContestView({ contest }: { contest: Contest }) {
  const deadline = useDeadline(contest.end_date);
  return (
    <Page
      title={contest.title}
      lead={
        <span className="contests-deadline">
          <Icon name="clock" className="contests-deadline__clock" />
          <span>
            {deadline.label} <strong>{deadline.date}</strong>
            {deadline.remaining !== null && ` · ${deadline.remaining}`}
          </span>
        </span>
      }
    >
      {contest.header_image && (
        // The title beside it names the contest, so the image adds no text.
        <img
          className="contests-header-image"
          src={contest.header_image}
          alt=""
          loading="eager"
          decoding="async"
        />
      )}
      <UploadButton contestId={contest.id} variant="primary" />
      <SanitizedHtml html={contest.notice_html ?? ''} />
      <UploadButton contestId={contest.id} variant="secondary" />
    </Page>
  );
}
