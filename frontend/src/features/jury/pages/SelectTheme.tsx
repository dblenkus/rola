import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { requestError } from '../../../shared/api/errors';
import { JuryContest } from '../../../shared/api/types';
import Button from '../../../shared/ui/Button';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import { getJuryContests } from '../api';
import ScoringProgress from '../components/ScoringProgress';
import './SelectTheme.css';

const SelectTheme: React.FC = () => {
  const [contests, setContests] = useState<JuryContest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  useEffect(() => {
    const fetchContests = async (): Promise<void> => {
      const { data } = await getJuryContests();
      setContests(data.results);
    };
    fetchContests().catch((error: unknown) => setError(requestError(error)));
  }, []);

  if (error) return <Message severity="error">{error}</Message>;
  if (!contests) return <LoadingProgress />;

  return (
    <Page title={t('jury_select_theme_title')}>
      {contests.length === 0 && (
        <p className="body jury-contests__empty">{t('jury_no_contests')}</p>
      )}
      {contests.map((contest) => (
        <section key={contest.id} className="jury-contest">
          <h2 className="jury-contest__title h3">{contest.title}</h2>
          <ul className="jury-themes">
            {contest.themes.map((theme) => (
              <li key={theme.id} className="jury-theme">
                <span className="jury-theme__title body">{theme.title}</span>
                <ScoringProgress
                  scored={theme.ratings_number}
                  total={theme.submissions_number}
                  label={t('jury_theme_progress', {
                    theme: theme.title,
                    scored: theme.ratings_number,
                    total: theme.submissions_number,
                  })}
                />
                <span className="jury-theme__action">
                  <Button
                    to={`/judge/contest/${contest.id}/theme/${theme.id}`}
                    aria-label={t('jury_open_theme', { theme: theme.title })}
                  >
                    {t('open')}
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </Page>
  );
};

export default SelectTheme;
