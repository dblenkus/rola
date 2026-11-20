import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';

import { requestError } from '../../../shared/api/errors';
import {
  Contest,
  ResultsAuthor,
  ResultsThemeSubmission,
} from '../../../shared/api/types';
import AwardMark from '../../../shared/ui/AwardMark';
import Icon from '../../../shared/ui/Icon';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import Table, {
  TableBody,
  TableCell,
  TableRow,
} from '../../../shared/ui/Table';
import groupBy from '../../../shared/utils/groupBy';
import { getContest } from '../../contests';
import { getThemeResults } from '../api';
import './ThemeResults.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

interface ThemeView {
  title: string;
  submissionsByAuthor: ResultsThemeSubmission[][];
}

// Results list Slovenian names, whatever the browser's locale.
const nameCollator = new Intl.Collator('sl');

const ThemeResults: React.FC = () => {
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemeView | null>(null);
  const [contest, setContest] = useState<Contest | null>(null);
  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }

  useEffect(() => {
    const fetch = async (): Promise<void> => {
      const { data } = await getThemeResults(themeId);
      setTheme({
        title: data.title,
        submissionsByAuthor: groupBy(
          data.submissions,
          (submission) => submission.author.id,
        ).sort(
          ([a], [b]) =>
            nameCollator.compare(a.author.last_name, b.author.last_name) ||
            nameCollator.compare(a.author.first_name, b.author.first_name),
        ),
      });
    };
    fetch().catch((error: unknown) => setError(requestError(error)));
  }, [themeId]);

  useEffect(() => {
    const fetchContest = async (): Promise<void> => {
      const { data } = await getContest(contestId);
      setContest(data);
    };
    fetchContest().catch((error: unknown) => setError(requestError(error)));
  }, [contestId]);

  const getAuthor = (submissions: ResultsThemeSubmission[]): ResultsAuthor => {
    const author = submissions[0]?.author;
    if (!author) {
      throw new Error('Submission group is empty');
    }
    return author;
  };

  const getAuthorReward = (author: ResultsAuthor): string => {
    if (author.reward_theme?.toString() !== themeId) return '';
    return author.reward || '';
  };

  // An award takes the place of "Accepted"; a plain entry shows nothing.
  const renderReward = (
    submission: ResultsThemeSubmission,
  ): React.ReactNode => {
    if (submission.reward_label)
      return <AwardMark name={submission.reward_label} />;
    if (submission.accepted)
      return (
        <span className="results-accepted label">
          <Icon name="check" className="results-accepted__icon" />
          {t('accepted')}
        </span>
      );
    return null;
  };

  // Only accepted entries open on their own page.
  const renderTitle = (submission: ResultsThemeSubmission): React.ReactNode => {
    const title = submission.title || t('results_untitled');
    if (!submission.accepted)
      return <span className="results-entry">{title}</span>;
    return (
      <Link
        className="results-entry results-entry__link"
        to={`/results/contest/${contestId}/theme/${themeId}/submission/${submission.id}`}
      >
        {title}
      </Link>
    );
  };

  if (error) return <Message severity="error">{error}</Message>;
  if (!theme || !contest) return <LoadingProgress />;

  return (
    <Page title={theme.title} lead={contest.title}>
      {theme.submissionsByAuthor.length ? (
        <Table>
          <TableBody>
            {theme.submissionsByAuthor.map((submissions) => {
              const author = getAuthor(submissions);
              const reward = getAuthorReward(author);
              let authorDetails = `${author.country}`;
              if (contest.school_show)
                authorDetails = `${author.school || '/'}`;
              if (author.club)
                authorDetails = t('author_details_with_club', {
                  details: authorDetails,
                  club: author.club,
                });
              return (
                <React.Fragment key={author.id}>
                  <TableRow>
                    <TableCell header>
                      {author.last_name}, {author.first_name}{' '}
                      <span className="results-author__details">
                        ({authorDetails})
                      </span>
                    </TableCell>
                    <TableCell align="end">
                      {reward && <AwardMark name={reward} />}
                    </TableCell>
                  </TableRow>
                  {submissions.map((submission) => (
                    <TableRow key={submission.id}>
                      <TableCell>{renderTitle(submission)}</TableCell>
                      <TableCell align="end">
                        {renderReward(submission)}
                      </TableCell>
                    </TableRow>
                  ))}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
      ) : (
        <p className="body results-empty">{t('no_published_results')}</p>
      )}
    </Page>
  );
};

export default ThemeResults;
