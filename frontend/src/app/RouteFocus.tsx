import { useEffect, useRef } from 'react';
import { NavigationType, useLocation, useNavigationType } from 'react-router';

// After a navigation to another path, moves focus to <main id="main">, so
// that keyboard and screen reader users start at the new page's content
// instead of the link they left. Focus stays where it is if a field inside
// main already took it. A link or a later redirect (PUSH, REPLACE) also
// scrolls to the top; Back and Forward (POP) leave the scroll position to the
// browser, which restores where the person was.
//
// Nothing happens on the first render, when only the query or the hash
// changes (filters, pages of a list), or on a redirect that replaces the
// entry the app opened at (/ to /contests, a private page to /login): that is
// still the first load, and the first Tab must reach the skip link.
export default function RouteFocus() {
  const { pathname, key } = useLocation();
  const navigationType = useNavigationType();
  // The first render's location; a fresh history entry's key is 'default'.
  const initialKey = useRef(key);
  const shown = useRef({ pathname, key });
  useEffect(() => {
    const previous = shown.current;
    shown.current = { pathname, key };
    if (pathname === previous.pathname) {
      return;
    }
    if (
      navigationType === NavigationType.Replace &&
      previous.key === initialKey.current
    ) {
      return;
    }
    if (navigationType !== NavigationType.Pop) {
      // The viewport's scroll position; jsdom has no window.scrollTo.
      document.documentElement.scrollTop = 0;
    }
    const main = document.getElementById('main');
    if (!main) {
      throw new Error('RouteFocus: the page has no element with id "main"');
    }
    if (!main.contains(document.activeElement)) {
      main.focus({ preventScroll: true });
    }
  }, [pathname, key, navigationType]);
  return null;
}
