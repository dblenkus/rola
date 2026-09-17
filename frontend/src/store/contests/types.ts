import { Contest as ApiContest } from '../../types/api';

export const STORE_CONTESTS = 'STORE_CONTESTS';

export interface Contest extends ApiContest {}

export type ContestsState = Array<Contest>;

interface StoreContestsAction {
    type: typeof STORE_CONTESTS;
    payload: {
        contests: Contest[];
    };
}

export type ContestsActionTypes = StoreContestsAction;
