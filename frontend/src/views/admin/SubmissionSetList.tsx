import { useParams } from 'react-router';
import React from 'react';

import { withStyles } from 'tss-react/mui';

import { Alert, Grid, Typography } from '@mui/material';

import ConfirmDialog from '../../components/Notifications/ConfirmDialog';

import { editListStyles } from '../../styles/general';
import SubmissionSetService from '../../services/SubmissionSetService';
import ContestService from '../../services/ContestService';
import { requestError } from '../../services/errors';
import { Contest, SubmissionSet } from '../../types/api';
import SubmissionSetTable from '../../components/SubmissionSetTable/SubmissionSetTable';
import LoadingProgress from '../../components/LoadingProgress';
import { WithTranslation, withTranslation } from 'react-i18next';

type StyleProps = {
  classes?: Record<keyof ReturnType<typeof editListStyles>, string>;
};

interface RouteMatchParams {
  contestId: string;
}

interface SubmissionSetListState {
  error: string | null;
  // A failed delete keeps the table so the admin can try again.
  deleteError: string | null;
  contest: Contest | null;
  pendingSubmissionSet: SubmissionSet | null;
  showDialog: boolean;
  reloadKey: number;
}

interface SubmissionSetListProps extends StyleProps, WithTranslation {
  match: { params: RouteMatchParams };
}

class SubmissionSetList extends React.Component<
  SubmissionSetListProps,
  SubmissionSetListState
> {
  constructor(props: SubmissionSetListProps) {
    super(props);

    this.state = {
      error: null,
      deleteError: null,
      contest: null,
      pendingSubmissionSet: null,
      showDialog: false,
      reloadKey: 0,
    };
  }

  async componentDidMount(): Promise<void> {
    await this.fetchData();
  }

  fetchData = async (): Promise<void> => {
    this.setState({ error: null });
    try {
      const {
        match: {
          params: { contestId },
        },
      } = this.props;

      const { data: contest } = await ContestService.getContest(contestId);

      this.setState({ contest });
    } catch (error) {
      this.setState({ error: requestError(error) });
    }
  };

  handleDelete = (pendingSubmissionSet: SubmissionSet): void => {
    this.setState({ pendingSubmissionSet, showDialog: true });
  };

  closeDialog = (): void =>
    this.setState({ pendingSubmissionSet: null, showDialog: false });

  processDelete = async (): Promise<void> => {
    const { pendingSubmissionSet } = this.state;
    if (!pendingSubmissionSet) return;

    this.setState({ deleteError: null });
    try {
      await SubmissionSetService.deleteSubmissionSet(pendingSubmissionSet.id);
      this.setState(({ reloadKey }) => ({ reloadKey: reloadKey + 1 }));
    } catch (error) {
      this.setState({ deleteError: requestError(error) });
    }
  };

  render(): React.ReactNode {
    const { contest, deleteError, error, reloadKey, showDialog } = this.state;
    const { t } = this.props;

    if (error) return <Alert severity="error">{error}</Alert>;
    if (!contest) return <LoadingProgress />;

    return (
      <>
        <Typography align="center" variant="h2">
          {contest?.title}
        </Typography>

        {deleteError && <Alert severity="error">{deleteError}</Alert>}
        <Grid size={{ xs: 12 }}>
          <SubmissionSetTable
            contestId={contest.id}
            reloadKey={reloadKey}
            onDelete={this.handleDelete}
          />
        </Grid>

        <ConfirmDialog
          open={showDialog}
          title={t('delete_confirmation_title')}
          onClose={this.closeDialog}
          onConfirm={this.processDelete}
        >
          {t('delete_confirmation') as React.ReactNode}
        </ConfirmDialog>
      </>
    );
  }
}

const RoutedView = withTranslation()(
  withStyles(SubmissionSetList, editListStyles),
);
export default function RouteView() {
  const params = useParams();
  const contestId = params.contestId;
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  return <RoutedView match={{ params: { contestId } }} />;
}
