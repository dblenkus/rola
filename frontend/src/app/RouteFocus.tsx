import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router';

// After a navigation to another path, scrolls to the top and moves focus to
// <main id="main">, so that keyboard and screen reader users start at the new
// page's content instead of the link they left. Focus stays where it is if a
// field inside main already took it. Nothing happens on the first render, or
// when only the query or the hash changes (filters, pages of a list).
export default function RouteFocus() {
  const { pathname } = useLocation();
  const shownPath = useRef(pathname);
  useEffect(() => {
    if (pathname === shownPath.current) {
      return;
    }
    shownPath.current = pathname;
    // The viewport's scroll position; jsdom has no window.scrollTo.
    document.documentElement.scrollTop = 0;
    const main = document.getElementById('main');
    if (!main) {
      throw new Error('RouteFocus: the page has no element with id "main"');
    }
    if (!main.contains(document.activeElement)) {
      main.focus({ preventScroll: true });
    }
  }, [pathname]);
  return null;
}
