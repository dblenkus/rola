import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

export type SeverityLevels = 'error' | 'info' | 'success' | 'warning';

export interface Notification {
  id: number;
  message: string;
  severity: SeverityLevels;
}

export type NotificationsState = Notification | null;

let nextId = 1;

const notificationsSlice = createSlice({
  name: 'notifications',
  initialState: null as NotificationsState,
  reducers: {
    addNotification: {
      reducer: (
        _state,
        action: PayloadAction<{ message: string; severity: SeverityLevels }>,
      ): NotificationsState => {
        const newNotification = { id: nextId, ...action.payload };
        nextId += 1;
        return newNotification;
      },
      prepare: (message: string, severity: SeverityLevels) => ({
        payload: { message, severity },
      }),
    },
    deleteMessage: {
      reducer: (
        state,
        action: PayloadAction<{ notificationId: number }>,
      ): NotificationsState =>
        state?.id === action.payload.notificationId ? null : state,
      prepare: (notificationId: number) => ({ payload: { notificationId } }),
    },
  },
});

export const { addNotification, deleteMessage } = notificationsSlice.actions;
export default notificationsSlice.reducer;
