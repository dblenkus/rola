import React from 'react';

import axios from 'axios';

import { WithTranslation, withTranslation } from 'react-i18next';

import Button, { ButtonRow } from '../../../shared/ui/Button';
import ConfirmDialog from '../../../shared/ui/ConfirmDialog';
import LoadingProgress from '../../../shared/ui/LoadingProgress';
import Message from '../../../shared/ui/Message';
import Page from '../../../shared/ui/Page';
import Table, {
  TableBody,
  TableCell,
  TableHead,
  TableRow,
} from '../../../shared/ui/Table';
import { requestError } from '../../../shared/api/errors';
import { Author, Contest, Submission } from '../../../shared/api/types';
import { asyncMap } from '../../../shared/utils/async';
import fetchAll from '../../../shared/api/fetchAll';
import groupBy from '../../../shared/utils/groupBy';
import { getActiveContests } from '../../contests';
import { deleteSubmission, getSubmissionsByContest } from '../api';
import './EditSubmissionsList.css';

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

  // The class has no useId; one list is on screen at a time.
  editReasonId = 'upload-edit-unavailable';

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
    const { t } = this.props;
    return <Page title={t('edit_submissions')}>{this.renderContent()}</Page>;
  }

  renderContent() {
    const { error, submissions: allSubmissions } = this.state;
    if (error) return <Message severity="error">{error}</Message>;
    if (!allSubmissions) return <LoadingProgress />;
    const { t } = this.props;
    const deleteAlert = this.state.deleteError && (
      <Message severity="error">{this.state.deleteError}</Message>
    );

    // A closed contest drops out of the reload after a refused delete, and
    // with it possibly every submission listed.
    if (!allSubmissions.length)
      return (
        <>
          {deleteAlert}
          <p className="body">{t('no_active_submissions')}</p>
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

    const columns = {
      contest: t('contest'),
      author: t('author'),
      themes: t('n_themes'),
      photos: t('n_photos'),
    };

    return (
      <>
        {deleteAlert}
        <Table label={t('edit_submissions')}>
          <TableHead>
            <TableRow>
              <TableCell>{columns.contest}</TableCell>
              <TableCell>{columns.author}</TableCell>
              <TableCell align="end">{columns.themes}</TableCell>
              <TableCell align="end">{columns.photos}</TableCell>
              <TableCell>
                <span className="visually-hidden">{t('upload_actions')}</span>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groupedSubmissions.map((group) => (
              <TableRow key={`${group.contest.id}-${group.author.id}`}>
                <TableCell label={columns.contest}>
                  {group.contest.title}
                </TableCell>
                <TableCell label={columns.author}>
                  {`${group.author.first_name} ${group.author.last_name}`}
                </TableCell>
                <TableCell label={columns.themes} align="end">
                  {group.submissions_n}
                </TableCell>
                <TableCell label={columns.photos} align="end">
                  {group.photos_n}
                </TableCell>
                <TableCell align="end">
                  <ButtonRow>
                    {/* Editing is not available yet. A locked button would
                        put its reason in every row; the line under the
                        table states it once. */}
                    <Button
                      variant="quiet"
                      size="dense"
                      inert
                      aria-describedby={this.editReasonId}
                    >
                      {t('edit')}
                    </Button>
                    <Button
                      size="dense"
                      onPress={this.openDialog(group.submissions)}
                    >
                      {t('delete')}
                    </Button>
                  </ButtonRow>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <p id={this.editReasonId} className="upload-submissions__note small">
          {t('upload_edit_unavailable')}
        </p>
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
