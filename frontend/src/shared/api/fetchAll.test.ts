import type { AxiosAdapter } from 'axios';
import { beforeEach, describe, expect, it } from 'vitest';
import { apiClient } from './client';
import type { PaginatedResponse } from './types';
import fetchAll from './fetchAll';

const origin = window.location.origin;
let requests: string[];

function page(
  results: number[],
  next: string | null,
): PaginatedResponse<number> {
  return { count: 3, results, next, previous: null };
}

function serve(pages: Record<string, PaginatedResponse<number>>): void {
  const adapter: AxiosAdapter = async (config) => {
    const url = new URL(apiClient.getUri(config), origin).href;
    requests.push(url);
    const data = pages[url];
    if (!data) {
      throw new Error(`Unexpected request: ${url}`);
    }
    return { config, data, status: 200, statusText: 'OK', headers: {} };
  };
  apiClient.defaults.adapter = adapter;
}

const firstPage = () => apiClient.get<PaginatedResponse<number>>('/contests');

const otherScheme = new URL(`${origin}/api/v1/contests?page=2`);
otherScheme.protocol = otherScheme.protocol === 'http:' ? 'https:' : 'http:';

beforeEach(() => {
  requests = [];
});

describe('paginated API reads', () => {
  it('follows relative and absolute links on the API origin', async () => {
    serve({
      [`${origin}/api/v1/contests`]: page([1], '/api/v1/contests?page=2'),
      [`${origin}/api/v1/contests?page=2`]: page(
        [2],
        `${origin}/api/v1/contests?page=3`,
      ),
      [`${origin}/api/v1/contests?page=3`]: page([3], null),
    });
    expect(await fetchAll(firstPage)).toEqual([1, 2, 3]);
    expect(requests).toEqual([
      `${origin}/api/v1/contests`,
      `${origin}/api/v1/contests?page=2`,
      `${origin}/api/v1/contests?page=3`,
    ]);
  });

  it.each([
    ['another origin', 'https://other.example/api/v1/contests?page=2'],
    ['another scheme', otherScheme.href],
    ['a path outside the API', `${origin}/django-admin/?page=2`],
    ['a sibling API prefix', `${origin}/api/v10/contests?page=2`],
  ])('does not follow a link to %s', async (_case, next) => {
    serve({ [`${origin}/api/v1/contests`]: page([1], next) });
    await expect(fetchAll(firstPage)).rejects.toThrow(
      `Invalid pagination URL: ${next}`,
    );
    expect(requests).toEqual([`${origin}/api/v1/contests`]);
  });

  it('stops when the pages link back to one already read', async () => {
    serve({
      [`${origin}/api/v1/contests`]: page([1], '/api/v1/contests?page=2'),
      [`${origin}/api/v1/contests?page=2`]: page(
        [2],
        '/api/v1/contests?page=2',
      ),
    });
    await expect(fetchAll(firstPage)).rejects.toThrow(
      'Invalid pagination URL: /api/v1/contests?page=2',
    );
    expect(requests).toEqual([
      `${origin}/api/v1/contests`,
      `${origin}/api/v1/contests?page=2`,
    ]);
  });
});
