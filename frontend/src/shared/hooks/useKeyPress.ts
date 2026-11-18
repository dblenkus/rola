import { useCallback, useEffect } from 'react';

const useKeyPress = (
  handler: (pressedKey: string, repeat: boolean) => void,
): void => {
  const downHandler = useCallback(
    ({ key, repeat }: KeyboardEvent): void => {
      handler(key, repeat);
    },
    [handler],
  );

  // Add event listeners.
  useEffect(() => {
    window.addEventListener('keydown', downHandler);
    // Remove event listeners on cleanup.
    return (): void => {
      window.removeEventListener('keydown', downHandler);
    };
  }, [downHandler]);
};

export default useKeyPress;
