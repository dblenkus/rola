import { STORE_CONTESTS, ContestsActionTypes, ContestsState } from './types';

const initialState: ContestsState = [];

const reducer = (state = initialState, action: ContestsActionTypes): ContestsState => {
    switch (action.type) {
        case STORE_CONTESTS:
            return action.payload.contests;
        default:
            return state;
    }
};

export default reducer;
