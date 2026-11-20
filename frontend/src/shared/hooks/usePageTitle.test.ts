import { renderHook } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import usePageTitle from './usePageTitle';

beforeEach(() => {
  document.title = '';
});

it('names the page in the document title, then Rola', () => {
  const { rerender } = renderHook(({ title }) => usePageTitle(title), {
    initialProps: { title: 'Contests' },
  });
  expect(document.title).toBe('Contests · Rola');
  rerender({ title: 'Natečaji' });
  expect(document.title).toBe('Natečaji · Rola');
});

it('uses Rola alone for an empty title', () => {
  renderHook(() => usePageTitle(''));
  expect(document.title).toBe('Rola');
});

it('leaves the title for the next page on unmount', () => {
  const { unmount } = renderHook(() => usePageTitle('Results'));
  unmount();
  expect(document.title).toBe('Results · Rola');
});
