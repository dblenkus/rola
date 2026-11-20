import React from 'react';
import { useTranslation } from 'react-i18next';

import Page from '../../../shared/ui/Page';
import './ResultsList.css';

// There is no list of published results yet: each contest links to its own.
const ResultsListView: React.FC = () => {
  const { t } = useTranslation();

  return (
    <Page title={t('results')}>
      <p className="body results-note">{t('results_reached_from_contest')}</p>
    </Page>
  );
};

export default ResultsListView;
