import {
  ADD_NOTIFICATION,
  DELETE_NOTIFICATION,
  NotificationsActionTypes,
  NotificationsState,
} from './types';

let nextId = 1;

const reducer = (
  state: NotificationsState = null,
  action: NotificationsActionTypes,
): NotificationsState => {
  switch (action.type) {
    case ADD_NOTIFICATION: {
      const newNotification = { id: nextId, ...action.payload };
      nextId += 1;
      return newNotification;
    }
    case DELETE_NOTIFICATION: {
      return state?.id === action.meta.notificationId ? null : state;
    }
    default: {
      return state;
    }
  }
};

export default reducer;
