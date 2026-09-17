import React from 'react';
import { connect, ConnectedProps } from 'react-redux';
import { withRouter, RouteComponentProps } from 'react-router';
import { Redirect } from 'react-router-dom';

import { AppState } from '../store';
import {
    authorUpdate,
    imageUpdate,
    submissionUpdate,
    uploadInit,
    uploadSubmit,
} from '../store/upload/actions';

import ContestService from '../services/ContestService';

import { DateChange, InputChange } from '../types/models';
import { Contest } from '../types/api';

import ContestField from '../components/Upload/Contest/ContestField';

interface RouteMatchParams {
    contestId: string;
}

interface UploadViewProps extends PropsFromRedux, RouteComponentProps<RouteMatchParams> {}

class UploadView extends React.Component<UploadViewProps> {
    async componentDidMount() {
        const { uploadInit } = this.props;
        const { contestId } = this.props.match.params;
        const { data: contest } = await ContestService.getContest(contestId);

        uploadInit(contest);
    }

    render(): React.ReactNode {
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
            return <Redirect to={`/contest/${contestId}/confirm`} />;
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

const mapDispatchToProps = (dispatch: any) => ({
    uploadInit: (contest: Contest) => dispatch(uploadInit(contest)),
    handleAuthorChange: (payload: InputChange | DateChange) => dispatch(authorUpdate(payload)),
    handleSubmissionChange: (theme_id: number, submission_id: number, payload: InputChange) =>
        dispatch(submissionUpdate(theme_id, submission_id, payload)),
    handleImageChange: (
        theme_id: number,
        submission_id: number,
        image_id: number,
        payload: { file: File | undefined },
    ): void => dispatch(imageUpdate(theme_id, submission_id, image_id, payload)),
    handleSubmit: () => dispatch(uploadSubmit()),
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

export default connector(withRouter(UploadView));
