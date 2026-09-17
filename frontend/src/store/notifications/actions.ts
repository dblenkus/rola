import { AppThunk } from '..';

import {
    ADD_NOTIFICATION,
    DELETE_NOTIFICATION,
    NotificationsActionTypes,
    SeverityLevels,
} from './types';

const addNotification = (message: string, severity: SeverityLevels): NotificationsActionTypes => ({
    type: ADD_NOTIFICATION,
    payload: { message, severity },
});

export const addNotificationError = (newMessage: string): NotificationsActionTypes =>
    addNotification(newMessage, 'error');

export const addNotificationWarning = (newMessage: string): NotificationsActionTypes =>
    addNotification(newMessage, 'warning');

export const addNotificationInfo = (newMessage: string): NotificationsActionTypes =>
    addNotification(newMessage, 'info');

export const addNotificationSuccess = (newMessage: string): NotificationsActionTypes =>
    addNotification(newMessage, 'success');

export const deleteMessage = (notificationId: number): NotificationsActionTypes => ({
    type: DELETE_NOTIFICATION,
    meta: { notificationId },
});

export const deleteMessageWithDelay = (notificationId: number): AppThunk => (dispatch) => {
    setTimeout(() => {
        dispatch(deleteMessage(notificationId));
    }, 5000);
};
