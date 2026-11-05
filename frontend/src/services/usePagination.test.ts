import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { httpError, page, serveApi } from '../test/api';
import { author } from '../test/fixtures';
import type { Author, PaginatedResponse } from '../types/api';
import { apiClient } from './Base';
import usePagination from './usePagination';

const list = (path: string) => (pageNumber: number, pageSize: number) =>
  apiClient.get<PaginatedResponse<Author>>(path, {
    params: { page: pageNumber, page_size: pageSize },
  });
const listA = list('/a');
const listB = list('/b');

describe('paginated lists', () => {
  it('clears a failed list and loads again for a new source', async () => {
    serveApi({
      'GET /a': (config) => {
        throw httpError(config, 403, { detail: 'Forbidden' });
      },
      'GET /b': () => page([author]),
    });
    const { result, rerender } = renderHook(usePagination<Author>, {
      initialProps: { source: listA, reloadKey: 0 },
    });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.error).toBe(
      'You do not have permission to perform this action.',
    );

    rerender({ source: listB, reloadKey: 0 });
    expect(result.current.isLoading).toBe(true);
    expect(result.current.error).toBeNull();
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.error).toBeNull();
    expect(result.current.data).toEqual([author]);
  });

  it('shows loading for a new page or reload until it arrives', async () => {
    const requests: string[] = [];
    serveApi({
      'GET /a': (config) => {
        requests.push(`page ${config.params.page}`);
        return { ...page([{ ...author, id: config.params.page }]), count: 40 };
      },
    });
    const { result, rerender } = renderHook(usePagination<Author>, {
      initialProps: { source: listA, reloadKey: 0 },
    });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    act(() => result.current.changePage(2));
    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.data.map(({ id }) => id)).toEqual([2]);

    rerender({ source: listA, reloadKey: 1 });
    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.page).toBe(2);
    expect(requests).toEqual(['page 1', 'page 2', 'page 2']);
  });
});
