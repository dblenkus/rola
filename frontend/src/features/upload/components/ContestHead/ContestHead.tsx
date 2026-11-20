import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import Icon from '../../../../shared/ui/Icon';
import usePageTitle from '../../../../shared/hooks/usePageTitle';
import { useDeadline } from '../../../contests';

interface ContestHeadProps {
  contestId: number;
  title: string;
  // When entries close, as the API sends it.
  endDate: string;
}

// The upload page's header after the design system's contest head: the back
// link to the contest, its title as the page's h1, and when entries close.
// The API has no organiser, so the line under the title is left out.
export default function ContestHead({
  contestId,
  title,
  endDate,
}: ContestHeadProps) {
  const { t } = useTranslation();
  const deadline = useDeadline(endDate);
  usePageTitle(title);

  return (
    <header className="rl-contest-head">
      <div className="rl-contest-head__top">
        <Link
          className="rl-contest-head__back"
          to={`/contest/${contestId}/details`}
          aria-label={t('upload_back_to_contest')}
        >
          <Icon name="chevron-left" />
        </Link>
        <div className="rl-contest-head__titles">
          <h1 className="rl-contest-head__title h3">{title}</h1>
        </div>
      </div>
      <p className="rl-contest-head__deadline small">
        <Icon name="clock" />
        <span>
          {deadline.label} <strong>{deadline.date}</strong>
          {deadline.remaining !== null && ` · ${deadline.remaining}`}
        </span>
      </p>
    </header>
  );
}
