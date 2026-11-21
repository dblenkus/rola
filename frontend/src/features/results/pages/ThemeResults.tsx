import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useTranslation } from 'react-i18next';

import { contentUnavailable, requestError } from '../../../shared/api/errors';
import fetchAll from '../../../shared/api/fetchAll';
import {
  Contest,
  ResultsAuthor,
  ResultsSubmission,
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
import { getResultsByTheme } from '../api';
import authorDetails from '../authorDetails';
import './ThemeResults.css';

interface RouteMatchParams {
  contestId: string;
  themeId: string;
}

// Results list Slovenian names, whatever the browser's locale.
const nameCollator = new Intl.Collator('sl');

const ThemeResults: React.FC = () => {
  const { t } = useTranslation();
  // The page stays mounted when only the theme changes, so the entries and a
  // failure to load them are kept with the theme they were loaded for.
  const [entries, setEntries] = useState<{
    themeId: string;
    byAuthor: ResultsSubmission[][];
  } | null>(null);
  const [entriesError, setEntriesError] = useState<{
    themeId: string;
    message: string;
  } | null>(null);
  const [contest, setContest] = useState<Contest | null>(null);
  const [contestError, setContestError] = useState<string | null>(null);
  const { contestId, themeId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!themeId) {
    throw new Error('Missing themeId route parameter');
  }

  useEffect(() => {
    // A theme left before its list answers keeps that answer off the page.
    let active = true;
    fetchAll(() => getResultsByTheme(themeId))
      .then((submissions) => {
        if (!active) return;
        setEntriesError(null);
        setEntries({
          themeId,
          byAuthor: groupBy(
            submissions,
            (submission) => submission.author.id,
          ).sort(
            ([a], [b]) =>
              nameCollator.compare(a.author.last_name, b.author.last_name) ||
              nameCollator.compare(a.author.first_name, b.author.first_name),
          ),
        });
      })
      .catch((error: unknown) => {
        const message = requestError(error);
        if (active) setEntriesError({ themeId, message });
      });
    return () => {
      active = false;
    };
  }, [themeId]);

  useEffect(() => {
    let active = true;
    getContest(contestId)
      .then(({ data }) => {
        if (!active) return;
        setContestError(null);
        setContest(data);
      })
      .catch((error: unknown) => {
        const message = requestError(error);
        if (active) setContestError(message);
      });
    return () => {
      active = false;
    };
  }, [contestId]);

  const getAuthor = (submissions: ResultsSubmission[]): ResultsAuthor => {
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
  const renderReward = (submission: ResultsSubmission): React.ReactNode => {
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
  const renderTitle = (submission: ResultsSubmission): React.ReactNode => {
    const title = submission.title || t('results_untitled');
    if (!submission.accepted) return title;
    return (
      <Link
        className="results-entry__link"
        to={`/results/contest/${contestId}/theme/${themeId}/submission/${submission.id}`}
      >
        {title}
      </Link>
    );
  };

  // Like the entries, the contest shown is the one in the address.
  const shownContest = contest?.id.toString() === contestId ? contest : null;
  // The results list of a theme that is not in the contest is empty, or a
  // 400 for an id that is not a number, so the contest's themes tell such a
  // theme from one without results, whatever its list answered.
  const theme = shownContest?.themes.find(
    ({ id }) => id.toString() === themeId,
  );
  const submissionsByAuthor =
    entries?.themeId === themeId ? entries.byAuthor : null;
  const message =
    shownContest && !theme
      ? contentUnavailable()
      : (contestError ??
        (entriesError?.themeId === themeId ? entriesError.message : null));
  if (message || !theme || !shownContest || !submissionsByAuthor) {
    // Until the theme is known, the page is named generically.
    return (
      <Page title={t('results')} titleHidden>
        {message ? (
          <Message severity="error">{message}</Message>
        ) : (
          <LoadingProgress />
        )}
      </Page>
    );
  }

  return (
    <Page title={theme.title} lead={shownContest.title}>
      {submissionsByAuthor.length ? (
        <Table>
          <TableBody>
            {submissionsByAuthor.map((submissions) => {
              const author = getAuthor(submissions);
              const reward = getAuthorReward(author);
              const details = authorDetails(t, {
                place: shownContest.school_visible
                  ? author.school
                  : author.country,
                club: author.club,
              });
              return (
                <React.Fragment key={author.id}>
                  <TableRow>
                    <TableCell header>
                      {author.last_name}, {author.first_name}
                      {details && (
                        <>
                          {' '}
                          <span className="results-author__details">
                            ({details})
                          </span>
                        </>
                      )}
                    </TableCell>
                    <TableCell align="end">
                      {reward && <AwardMark name={reward} />}
                    </TableCell>
                  </TableRow>
                  {submissions.map((submission) => (
                    <TableRow key={submission.id}>
                      <TableCell className="results-entry">
                        {renderTitle(submission)}
                      </TableCell>
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
