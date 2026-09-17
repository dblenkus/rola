import { useCallback, useEffect } from 'react';

const useKeyPress = (handler: (pressedKey: string) => void): void => {
    const downHandler = useCallback(
        ({ key }: KeyboardEvent): void => {
            handler(key);
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
