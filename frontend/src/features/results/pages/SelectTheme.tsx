import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from 'react-router';

import { requestError } from '../../../shared/api/errors';
import { Contest } from '../../../shared/api/types';
import Button from '../../../shared/ui/Button';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import Table, {
  TableBody,
  TableCell,
  TableRow,
} from '../../../shared/ui/Table';
import { getContest } from '../../contests';

interface RouteMatchParams {
  contestId: string;
}

const SelectTheme: React.FC = () => {
  const [contest, setContest] = useState<null | Contest>(null);
  const [error, setError] = useState<string | null>(null);
  const { contestId } = useParams<keyof RouteMatchParams>();
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }

  const { t } = useTranslation();

  useEffect(() => {
    const fetchContest = async (): Promise<void> => {
      const { data } = await getContest(contestId);
      setContest(data);
    };
    fetchContest().catch((error: unknown) => setError(requestError(error)));
  }, [contestId]);

  if (error || !contest) {
    // Until the contest is known, the page is named generically.
    return (
      <Page title={t('results')} titleHidden>
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
      <Table>
        <TableBody>
          {contest.themes.map((theme) => (
            <TableRow key={theme.id}>
              <TableCell header>{theme.title}</TableCell>
              <TableCell align="end">
                <Button
                  to={`/results/contest/${contest.id}/theme/${theme.id}`}
                  aria-label={t('results_view_theme', { theme: theme.title })}
                >
                  {t('view')}
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Page>
  );
};

export default SelectTheme;
