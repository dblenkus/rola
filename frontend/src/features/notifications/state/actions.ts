import { addNotification } from './reducer';

export { deleteMessage } from './reducer';

export const addNotificationError = (newMessage: string) =>
  addNotification(newMessage, 'error');

export const addNotificationWarning = (newMessage: string) =>
  addNotification(newMessage, 'warning');

export const addNotificationInfo = (newMessage: string) =>
  addNotification(newMessage, 'info');

export const addNotificationSuccess = (newMessage: string) =>
  addNotification(newMessage, 'success');
