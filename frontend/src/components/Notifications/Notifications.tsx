import React from 'react';
import { useDispatch, useSelector } from 'react-redux';

import Snackbar from '@material-ui/core/Snackbar';
import Alert from '@material-ui/lab/Alert';

import { deleteMessage, deleteMessageWithDelay } from '../../store/notifications/actions';
import { Notification } from '../../store/notifications/types';
import { isUndefined } from 'util';

const Notifications: React.FC = () => {
    const dispatch = useDispatch();
    const notification: Notification | undefined = useSelector((store: any) => {
        const { notifications } = store;
        return notifications[notifications.length - 1];
    });
    if (notification) {
        dispatch(deleteMessageWithDelay(notification.id));
    }

    const handleClose = () => {
        dispatch(deleteMessage(notification?.id || -1));
    };

    return !isUndefined(notification) ? (
        <Snackbar
            open={!isUndefined(notification)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            transitionDuration={{ enter: 500 }}
            // This is required to trigger the animation on the following notification.
            key={notification.id}
        >
            <Alert severity={notification.severity} variant="filled" onClose={handleClose}>
                {notification.message}
            </Alert>
        </Snackbar>
    ) : (
        <></>
    );
};

export default Notifications;
