import React from 'react';

import axios from 'axios';

import { WithTranslation, withTranslation } from 'react-i18next';

import {
  Alert,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';

import ConfirmDialog from '../../../shared/ui/ConfirmDialog';
import LoadingProgress from '../../../shared/ui/LoadingProgress';

import { tableButtonSx } from '../../../shared/ui/styles';
import { requestError } from '../../../shared/api/errors';
import { Author, Contest, Submission } from '../../../shared/api/types';
import { asyncMap } from '../../../shared/utils/async';
import fetchAll from '../../../shared/api/fetchAll';
import groupBy from '../../../shared/utils/groupBy';
import { getActiveContests } from '../../contests';
import { deleteSubmission, getSubmissionsByContest } from '../api';

type EditSubmissionListProps = WithTranslation;

interface EditSubmissionsListState {
  error: string | null;
  // A failed delete keeps the list so the participant can try again.
  deleteError: string | null;
  contests: Contest[];
  submissions: Submission[] | null;
  showDialog: boolean;
  pendingSubmissions: Submission[];
}

interface GroupedSubmissions {
  contest: Contest;
  author: Author;
  submissions: Submission[];
  submissions_n: number;
  photos_n: number;
}

class EditSubmissionsList extends React.Component<
  EditSubmissionListProps,
  EditSubmissionsListState
> {
  state: EditSubmissionsListState = {
    error: null,
    deleteError: null,
    contests: [],
    submissions: null,
    showDialog: false,
    pendingSubmissions: [],
  };

  async fetchSubmissions() {
    this.setState({ error: null });
    try {
      const getContestSubmissions = (contest: Contest) =>
        fetchAll(() => getSubmissionsByContest(contest.id));

      const contests = await fetchAll(getActiveContests);
      const submissions = (
        await asyncMap(contests, getContestSubmissions)
      ).flat();

      this.setState({ contests, submissions });
    } catch (error) {
      this.setState({ error: requestError(error) });
    }
  }

  async componentDidMount() {
    await this.fetchSubmissions();
  }

  getSubmissionsForContest = (
    contest: Contest,
    submissions: Submission[],
  ): Submission[] => {
    const themeIds = contest.themes.map((theme) => theme.id);
    return submissions.filter((submission) =>
      themeIds.includes(submission.theme),
    );
  };

  openDialog = (pendingSubmissions: Submission[]) => () => {
    this.setState({ showDialog: true, pendingSubmissions });
  };

  closeDialog = () => this.setState({ showDialog: false });

  processDelete = async () => {
    const { pendingSubmissions } = this.state;
    this.setState({ deleteError: null });
    // One at a time, so a failure leaves no request running and the reload
    // below shows exactly which photographs are left.
    try {
      for (const submission of pendingSubmissions) {
        await deleteSubmission(submission.id);
      }
    } catch (error) {
      // Only the owner's submissions are listed, so a refusal means the
      // contest has closed.
      const closed =
        axios.isAxiosError(error) && error.response?.status === 403;
      this.setState({
        deleteError: closed
          ? this.props.t('contest_closed_delete')
          : requestError(error),
      });
    }
    await this.fetchSubmissions();
  };

  render() {
    const { error, submissions: allSubmissions } = this.state;
    if (error) return <Alert severity="error">{error}</Alert>;
    if (!allSubmissions) return <LoadingProgress />;
    const { t } = this.props;
    const deleteAlert = this.state.deleteError && (
      <Alert severity="error">{this.state.deleteError}</Alert>
    );

    // A closed contest drops out of the reload after a refused delete, and
    // with it possibly every submission listed.
    if (!allSubmissions.length)
      return (
        <>
          {deleteAlert}
          <Typography align="center" variant="h3">
            {t('no_active_submissions')}
          </Typography>
        </>
      );

    const groupedSubmissions: GroupedSubmissions[] = [];
    this.state.contests.forEach((contest) => {
      const contestSubmissions = this.getSubmissionsForContest(
        contest,
        allSubmissions,
      );
      for (const submissions of groupBy(
        contestSubmissions,
        (submission) => submission.author.id,
      )) {
        const { author } = submissions[0];
        const submissions_n = new Set(submissions.map(({ theme }) => theme))
          .size;
        const photos_n = submissions.reduce(
          (total, submission) => total + submission.files.length,
          0,
        );

        groupedSubmissions.push({
          contest,
          author,
          submissions,
          submissions_n,
          photos_n,
        });
      }
    });

    return (
      <>
        {deleteAlert}
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('contest')}</TableCell>
                <TableCell>{t('author')}</TableCell>
                <TableCell>{t('n_themes')}</TableCell>
                <TableCell>{t('n_photos')}</TableCell>
                <TableCell></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {groupedSubmissions.map((group) => (
                <TableRow key={`${group.contest.id}-${group.author.id}`}>
                  <TableCell>{group.contest.title}</TableCell>
                  <TableCell>
                    {`${group.author.first_name} ${group.author.last_name}`}
                  </TableCell>
                  <TableCell>{group.submissions_n}</TableCell>
                  <TableCell>{group.photos_n}</TableCell>
                  <TableCell align="right">
                    <Tooltip title={t('not_yet_available')} placement="top">
                      <span>
                        <Button variant="text" sx={tableButtonSx} disabled>
                          {t('edit')}
                        </Button>
                      </span>
                    </Tooltip>
                    <Button
                      variant="text"
                      sx={tableButtonSx}
                      color="secondary"
                      onClick={this.openDialog(group.submissions)}
                    >
                      {t('delete')}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <ConfirmDialog
          open={this.state.showDialog}
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

export default withTranslation()(EditSubmissionsList);
