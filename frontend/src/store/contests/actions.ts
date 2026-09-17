import { Dispatch } from 'redux';

import { STORE_CONTESTS, Contest, ContestsActionTypes } from './types';

import ContestService from '../../services/ContestService';

export const storeContests = (contests: Contest[]): ContestsActionTypes => ({
    type: STORE_CONTESTS,
    payload: { contests },
});

export const loadContests = (): Function => async (dispatch: Dispatch) => {
    const resp = await ContestService.getActiveContests();
    dispatch(storeContests(resp.data.results));
};
