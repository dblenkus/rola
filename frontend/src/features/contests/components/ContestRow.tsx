import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import type { Contest } from '../../../shared/api/types';
import Button from '../../../shared/ui/Button';
import Icon from '../../../shared/ui/Icon';
import useDeadline from '../hooks/useDeadline';
import './ContestRow.css';

interface ContestRowProps {
  contest: Contest;
}

// One contest in the entrant's list, after the design system's ContestRow:
// the name and description, the closing date at the right, and the action.
// The API has no stage or participation, so those columns are left out.
export default function ContestRow({ contest }: ContestRowProps) {
  const { t } = useTranslation();
  const deadline = useDeadline(contest.end_date);

  return (
    <li className="contests-row">
      <div className="contests-row__contest">
        <h2 className="contests-row__title h3">
          <Link
            className="rl-contest-row__name"
            to={`/contest/${contest.id}/details`}
          >
            {contest.title}
          </Link>
        </h2>
        {contest.description && (
          <p className="contests-row__description small">
            {contest.description}
          </p>
        )}
      </div>
      <p className="contests-row__date">
        <Icon name="clock" className="contests-row__clock" />
        <span className="rl-contest-row__date-label caption">
          {deadline.label}
        </span>{' '}
        <span className="rl-contest-row__date-value body">{deadline.date}</span>
        {deadline.remaining !== null && (
          <>
            {' '}
            <span className="rl-contest-row__date-note small">
              ({deadline.remaining})
            </span>
          </>
        )}
      </p>
      <div className="contests-row__action">
        <Button variant="secondary" to={`/contest/${contest.id}/upload`}>
          {t('open')}
        </Button>
      </div>
    </li>
  );
}
