import Snackbar from '@mui/material/Snackbar';
import Alert from '@mui/material/Alert';
import { useAppDispatch, useAppSelector } from '../../store';
import { deleteMessage } from '../../store/notifications/actions';

export default function Notifications() {
  const dispatch = useAppDispatch();
  const notification = useAppSelector((state) => state.notifications);
  if (!notification) {
    return null;
  }
  const close = () => {
    dispatch(deleteMessage(notification.id));
  };
  return (
    <Snackbar
      key={notification.id}
      open
      autoHideDuration={5000}
      onClose={(_, reason) => {
        if (reason !== 'clickaway') {
          close();
        }
      }}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
    >
      <Alert severity={notification.severity} variant="filled" onClose={close}>
        {notification.message}
      </Alert>
    </Snackbar>
  );
}
