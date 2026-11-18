import {
  JuryActionTypes,
  JuryState,
  PERFORM_INITIALIZE,
  SET_SUBMISSION,
  SET_PREVIOUS_SUBMISSION,
  SET_NEXT_SUBMISSION,
} from './types';

const initialState: JuryState = {
  contest: null,
  theme: null,
  submissions: null,
  currentIndex: 0,
};

const reducer = (state = initialState, action: JuryActionTypes): JuryState => {
  switch (action.type) {
    case PERFORM_INITIALIZE:
      return { ...state, ...action.payload };
    case SET_SUBMISSION: {
      const { submissions } = state;
      const { submissionId } = action.payload;
      const newIndex =
        submissions?.findIndex((s) => s.id === submissionId) ?? -1;
      return { ...state, currentIndex: Math.max(newIndex, 0) };
    }
    // A move requested before a reload changed the list stays within it.
    case SET_PREVIOUS_SUBMISSION:
      return { ...state, currentIndex: Math.max(state.currentIndex - 1, 0) };
    case SET_NEXT_SUBMISSION:
      return {
        ...state,
        currentIndex: Math.min(
          state.currentIndex + 1,
          Math.max((state.submissions?.length ?? 0) - 1, 0),
        ),
      };

    default:
      return state;
  }
};

export default reducer;
