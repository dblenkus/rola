import { useEffect } from 'react';

// Sets the document title to "<title> · Rola", or "Rola" when the title is
// empty. Nothing is restored on unmount: the next page sets its own.
const usePageTitle = (title: string): void => {
  useEffect(() => {
    document.title = title ? `${title} · Rola` : 'Rola';
  }, [title]);
};

export default usePageTitle;
