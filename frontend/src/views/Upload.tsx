import React from 'react';
import { connect, ConnectedProps } from 'react-redux';

import { Navigate, useParams } from 'react-router';

import { Alert } from '@mui/material';

import type { AppDispatch, AppState } from '../store';
import {
  authorUpdate,
  imageUpdate,
  submissionUpdate,
  uploadInit,
  uploadSubmit,
} from '../store/upload/actions';

import ContestService from '../services/ContestService';
import { requestError } from '../services/errors';

import { DateChange, InputChange } from '../types/models';
import { Contest } from '../types/api';

import ContestField from '../components/Upload/Contest/ContestField';

interface RouteMatchParams {
  contestId: string;
}

interface UploadViewProps extends PropsFromRedux {
  match: { params: RouteMatchParams };
}

interface UploadViewState {
  error: string | null;
}

class UploadView extends React.Component<UploadViewProps, UploadViewState> {
  state: UploadViewState = { error: null };

  async componentDidMount() {
    const { uploadInit } = this.props;
    const { contestId } = this.props.match.params;
    try {
      const { data: contest } = await ContestService.getContest(contestId);
      uploadInit(contest);
    } catch (error) {
      this.setState({ error: requestError(error) });
    }
  }

  render(): React.ReactNode {
    if (this.state.error)
      return <Alert severity="error">{this.state.error}</Alert>;
    const {
      contest,
      handleAuthorChange,
      handleSubmissionChange,
      handleImageChange,
      handleSubmit,
      redirect,
      uploading,
    } = this.props;
    const { contestId } = this.props.match.params;

    if (redirect) {
      return <Navigate to={`/contest/${contestId}/confirm`} replace />;
    }

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
  uploadInit: (contest: Contest) => dispatch(uploadInit(contest)),
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
  const contestId = params.contestId;
  if (!contestId) {
    throw new Error('Missing contestId route parameter');
  }
  return <RoutedView match={{ params: { contestId } }} />;
}
