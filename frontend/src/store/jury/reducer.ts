import _ from 'lodash';

import {
    JuryActionTypes,
    JuryState,
    PERFORM_INITIALIZE,
    SET_SUBMISSION,
    SET_PREVIOUS_SUBMISSION,
    SET_NEXT_SUBMISSION,
} from './types';

const initialState: JuryState = {
    isLoading: true,
    contest: null,
    theme: null,
    submissions: null,
    currentIndex: 0,
};

const reducer = (state = initialState, action: JuryActionTypes): JuryState => {
    switch (action.type) {
        case PERFORM_INITIALIZE:
            return { ...state, ...action.payload, isLoading: false };
        case SET_SUBMISSION: {
            const { submissions } = state;
            const { submissionId } = action.payload;
            const newIndex = _.findIndex(submissions, (s) => s.id === submissionId);
            return { ...state, currentIndex: _.max([newIndex, 0]) as number };
        }
        case SET_PREVIOUS_SUBMISSION:
            return { ...state, currentIndex: state.currentIndex - 1 };
        case SET_NEXT_SUBMISSION:
            return { ...state, currentIndex: state.currentIndex + 1 };

        default:
            return state;
    }
};

export default reducer;
