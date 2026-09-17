import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useHistory, useParams, Redirect } from 'react-router-dom';
import { connect, ConnectedProps } from 'react-redux';
import _ from 'lodash';
import { parse } from 'query-string';

import SubmissionRater from '../../components/Jury/SubmissionRater';

import { AppState, AppDispatch } from '../../store';

import {
    getCurrentSubmission,
    getIsNext,
    getIsPrevious,
    initializeStore,
    setNextSubmission,
    setPreviousSubmission,
} from '../../store/jury/actions';
import RatingService from '../../services/RatingService';
import useKeyPress from '../../hooks/useKeyPress';
import LoadingProgress from '../../components/LoadingProgress';

interface RouteMatchParams {
    contestId: string;
    themeId: string;
}

const RateSubmission: React.FC<PropsFromRedux> = ({
    submission,
    theme,
    isLoading,
    isPrevious,
    isNext,
    initialize,
    nextSubmission,
    previousSubmission,
}: PropsFromRedux) => {
    const [rating, setRating] = useState(0);
    const [close, setClose] = useState(false);

    const { contestId, themeId } = useParams<RouteMatchParams>();
    const history = useHistory();
    const submissionId = useRef(
        parse(history.location.search, { parseNumbers: true }).submission as number | undefined,
    );

    const fetchRaiting = useCallback(async (): Promise<void> => {
        if (!submission) return;
        const { data: ratings } = await RatingService.getForSubmission(submission.id);
        setRating(ratings.results[0]?.rating || 0);
    }, [submission]);

    const updateRating = async (newRating: number): Promise<void> => {
        if (!submission) return;
        setRating(newRating);
        await RatingService.updateForSubmission(submission.id, newRating);
        if (isNext) nextSubmission();
    };

    // Initialize the store.
    useEffect(() => {
        initialize(contestId, themeId, submissionId.current);
    }, [contestId, themeId, initialize]);

    // Store submission id in url.
    useEffect(() => {
        if (submission && submissionId.current !== submission.id) {
            history.push(`?submission=${submission.id}`);
            submissionId.current = submission.id;
        }
    }, [history, submission]);

    useEffect(() => {
        fetchRaiting();
    }, [fetchRaiting]);

    useKeyPress((value: string) => {
        const parsedNumber = parseInt(value, 10);
        if (!_.isNaN(parsedNumber)) {
            updateRating(parsedNumber || 10);
        } else if (value === 'ArrowRight' && isNext) {
            nextSubmission();
        } else if (value === 'ArrowLeft' && isPrevious) {
            previousSubmission();
        }
    });

    const handleClose = () => setClose(true);

    if (close) return <Redirect to={`/judge/contest/${contestId}/theme/${themeId}`} push />;

    if (isLoading || !submission) return <LoadingProgress />;

    return (
        <div style={{ position: 'absolute', width: '100%', left: 0, right: 0 }}>
            <SubmissionRater
                submission={submission}
                rating={rating}
                isSeries={theme?.is_series || false}
                close={handleClose}
                isPrevious={isPrevious}
                isNext={isNext}
                previousSubmission={previousSubmission}
                nextSubmission={nextSubmission}
                updateRating={updateRating}
            />
        </div>
    );
};

const mapStateToProps = (state: AppState) => ({
    ...state.jury,
    submission: getCurrentSubmission(state),
    isPrevious: getIsPrevious(state),
    isNext: getIsNext(state),
});

const mapDispatchToProps = (dispatch: AppDispatch) => ({
    initialize: (contestId: string, themeId: string, submissionId: number | undefined): void =>
        dispatch(initializeStore(contestId, themeId, submissionId)),
    previousSubmission: () => dispatch(setPreviousSubmission()),
    nextSubmission: () => dispatch(setNextSubmission()),
});

const connector = connect(mapStateToProps, mapDispatchToProps);

type PropsFromRedux = ConnectedProps<typeof connector>;

export default connector(RateSubmission);
