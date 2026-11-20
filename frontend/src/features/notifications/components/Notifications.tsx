import {
  useEffect,
  useState,
  type FocusEvent,
  type KeyboardEvent,
} from 'react';
import { useAppDispatch, useAppSelector } from '../../../app/store';
import Message from '../../../shared/ui/Message';
import { deleteMessage } from '../state/actions';
import type { Notification } from '../state/reducer';
import './Notifications.css';

// How long a notification stays while nobody points at it or works in it.
const AUTO_HIDE_MS = 5000;

export default function Notifications() {
  const notification = useAppSelector((state) => state.notifications);
  if (!notification) {
    return null;
  }
  // A new notification starts its own timer.
  return <Toast key={notification.id} notification={notification} />;
}

// The notification at the bottom of the screen. It never takes focus. Its
// timer waits while the pointer is over it or focus is inside it, and starts
// over when both leave, so it can be read and closed in time (WCAG 2.2.1).
function Toast({ notification }: { notification: Notification }) {
  const dispatch = useAppDispatch();
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const paused = hovered || focused;

  const { id } = notification;
  useEffect(() => {
    if (paused) return undefined;
    const timer = window.setTimeout(() => {
      dispatch(deleteMessage(id));
    }, AUTO_HIDE_MS);
    return () => window.clearTimeout(timer);
  }, [dispatch, id, paused]);

  const close = (): void => {
    dispatch(deleteMessage(id));
  };

  const handleBlur = (event: FocusEvent<HTMLDivElement>): void => {
    if (
      !(event.relatedTarget instanceof Node) ||
      !event.currentTarget.contains(event.relatedTarget)
    ) {
      setFocused(false);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    if (event.key === 'Escape') close();
  };

  return (
    <div
      className="notifications"
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
      onFocus={() => setFocused(true)}
      onBlur={handleBlur}
      onKeyDown={handleKeyDown}
    >
      <Message severity={notification.severity} onClose={close}>
        {notification.message}
      </Message>
    </div>
  );
}
