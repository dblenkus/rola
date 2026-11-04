import React from 'react';
import { connect, ConnectedProps } from 'react-redux';

import { useNavigate, useParams } from 'react-router';

import { Alert } from '@mui/material';

import type { AppDispatch, AppState } from '../store';
import {
  authorUpdate,
  imageUpdate,
  submissionUpdate,
  uploadInit,
  uploadSubmit,
} from '../store/upload/actions';

import { userContext } from '../components/Auth/AuthProvider';
import ContestService from '../services/ContestService';
import { requestError } from '../services/errors';

import { DateChange, InputChange } from '../types/models';
import { Contest } from '../types/api';

import ContestField from '../components/Upload/Contest/ContestField';
import LoadingProgress from '../components/LoadingProgress';

interface RouteMatchParams {
  contestId: string;
}

interface UploadViewProps extends PropsFromRedux {
  account: string;
  match: { params: RouteMatchParams };
  onUploaded: () => void;
}

interface UploadViewState {
  error: string | null;
}

class UploadView extends React.Component<UploadViewProps, UploadViewState> {
  state: UploadViewState = { error: null };
  // The contest can load after this view was left for another contest or
  // account; opening its form then would replace the one on screen.
  mounted = false;

  async componentDidMount() {
    this.mounted = true;
    const { account, uploadInit } = this.props;
    const { contestId } = this.props.match.params;
    try {
      const { data: contest } = await ContestService.getContest(contestId);
      if (!this.mounted) return;
      uploadInit(contest, account);
    } catch (error) {
      if (!this.mounted) return;
      this.setState({ error: requestError(error) });
    }
  }

  componentWillUnmount() {
    this.mounted = false;
  }

  componentDidUpdate(prev: UploadViewProps) {
    // An upload can finish while another contest or account is on screen;
    // only the view that showed the uploaded form moves on to its
    // confirmation.
    const { account, match, uploadedKey } = this.props;
    const shown =
      prev.owner === account &&
      prev.contestId === Number(match.params.contestId);
    if (shown && prev.uploadKey !== null && uploadedKey === prev.uploadKey) {
      this.props.onUploaded();
    }
  }

  render(): React.ReactNode {
    if (this.state.error)
      return <Alert severity="error">{this.state.error}</Alert>;
    // Until the form is opened for this account, the store may hold another
    // account's form, which must not be shown or submitted.
    if (this.props.owner !== this.props.account) return <LoadingProgress />;
    const {
      contestId,
      contest,
      handleAuthorChange,
      handleSubmissionChange,
      handleImageChange,
      handleSubmit,
      uploading,
    } = this.props;
    // Until this contest loads, the store holds an empty form or another
    // contest's, which must not be shown or submitted here.
    if (contestId !== Number(this.props.match.params.contestId))
      return <LoadingProgress />;

    return (
      <ContestField
        contest={contest}
        handleAuthorChange={handleAuthorChange}
        handleSubmissionChange={handleSubmissionChange}
        handleImageChange={handleImageChange}
        handleSubmit={handleSubmit}
        uploading={uploading}
      />
    );
  }
}

const mapStateToProps = (state: AppState) => ({ ...state.upload });

const mapDispatchToProps = (dispatch: AppDispatch) => ({
  uploadInit: (contest: Contest, owner: string) =>
    dispatch(uploadInit(contest, owner)),
  handleAuthorChange: (payload: InputChange | DateChange) =>
    dispatch(authorUpdate(payload)),
  handleSubmissionChange: (
    theme_id: number,
    submission_id: number,
    payload: InputChange,
  ) => dispatch(submissionUpdate(theme_id, submission_id, payload)),
  handleImageChange: (
    theme_id: number,
    submission_id: number,
    image_id: number,
    payload: { file: File | undefined },
  ): Promise<void> =>
    dispatch(imageUpdate(theme_id, submission_id, image_id, payload)),
  handleSubmit: () => dispatch(uploadSubmit()),
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

const RoutedView = connector(UploadView);
export default function RouteView() {
  const params = useParams();
  const navigate = useNavigate();
  const { user } = React.useContext(userContext);
  const contestId = params.contestId;
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  if (!user) {
    throw new Error('The upload form needs a session');
  }
  return (
    <RoutedView
      // Opened afresh when another account signs in, from another tab too.
      key={user.email}
      account={user.email}
      match={{ params: { contestId } }}
      onUploaded={() =>
        navigate(`/contest/${contestId}/confirm`, { replace: true })
      }
    />
  );
}
