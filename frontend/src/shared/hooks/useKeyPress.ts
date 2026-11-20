import { useEffect, useEffectEvent } from 'react';

interface KeyPressOptions {
  // Listens only while true, so that the person can turn the shortcuts off.
  enabled?: boolean;
}

// A text field, list box or editable region uses the keys for itself.
// jsdom has no isContentEditable, so the attribute decides. A key sent to the
// window has no element as its target.
function isEditable(target: EventTarget | null): boolean {
  return (
    target instanceof Element &&
    target.closest(
      'input, textarea, select, [contenteditable]:not([contenteditable="false"])',
    ) !== null
  );
}

// Calls `handler` with each key pressed anywhere on the page, and whether the
// key is repeating because it is held down. Keys pressed with Ctrl, Alt or
// Meta belong to the browser and the system, and keys typed into an editable
// element belong to it, so neither reaches the handler. A handler that
// returns true has used the key, which then does nothing else, such as
// scrolling the page.
const useKeyPress = (
  handler: (pressedKey: string, repeat: boolean) => boolean | void,
  { enabled = true }: KeyPressOptions = {},
): void => {
  const onKeyDown = useEffectEvent((event: KeyboardEvent): void => {
    if (event.ctrlKey || event.altKey || event.metaKey) return;
    if (isEditable(event.target)) return;
    if (handler(event.key, event.repeat) === true) event.preventDefault();
  });

  useEffect(() => {
    if (!enabled) return;
    const listener = (event: KeyboardEvent) => onKeyDown(event);
    window.addEventListener('keydown', listener);
    return (): void => {
      window.removeEventListener('keydown', listener);
    };
  }, [enabled]);
};

export default useKeyPress;
