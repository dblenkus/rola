import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import { httpError, page, serveApi, signIn } from '../test/api';
import { open } from '../test/app';
import { contest, submissionSet } from '../test/fixtures';
import type { PaginatedResponse, Payment } from '../shared/api/types';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

describe('admin submission list', () => {
  it('reloads the list after a confirmed delete only', async () => {
    signIn();
    const adapter = serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'DELETE /submissionset/5': () => null,
    });
    const listRequests = () =>
      adapter.mock.calls.filter(
        ([config]) =>
          config.method === 'get' && config.url === '/submissionset',
      ).length;
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'No',
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(listRequests()).toBe(1);

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    await waitFor(() => expect(listRequests()).toBe(2));
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'delete'),
    ).toHaveLength(1);
  });

  it('shows the previous page after deleting the last row of a page', async () => {
    signIn();
    let sets = Array.from({ length: 21 }, (_, index) => ({
      ...submissionSet,
      id: index + 1,
    }));
    serveApi({
      'GET /contests/1': () => contest,
      // Like the API, answers a page past the end with 404.
      'GET /submissionset': (config) => {
        const pageNumber: number = config.params.page;
        const pageSize: number = config.params.page_size;
        const results = sets.slice(
          (pageNumber - 1) * pageSize,
          pageNumber * pageSize,
        );
        if (pageNumber > 1 && !results.length) {
          throw httpError(config, 404, { detail: 'Invalid page.' });
        }
        return { ...page(results), count: sets.length };
      },
      'GET /payment': () => page([]),
      'DELETE /submissionset/21': () => {
        sets = sets.slice(0, 20);
        return null;
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(
      await screen.findByRole('button', { name: 'Go to next page' }),
    );
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    expect(await screen.findByText('1-20 of 20')).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(20);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows stored payments and reloads them after a change', async () => {
    signIn();
    let paid = true;
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': (): PaginatedResponse<Payment> =>
        page([
          {
            id: 8,
            created: '2026-01-01T00:00:00Z',
            modified: '2026-01-01T00:00:00Z',
            submission_set: submissionSet.id,
            paid,
          },
        ]),
      'POST /payment': (config) => {
        paid = JSON.parse(config.data).paid;
        return {};
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked());

    await user.click(screen.getByRole('checkbox'));
    await waitFor(() => expect(screen.getByRole('checkbox')).not.toBeChecked());
    expect(paid).toBe(false);
  });

  it('requests no payments for an empty list', async () => {
    signIn();
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': () => page([]),
    });
    open('/admin/contest/1/submissions');
    expect(await screen.findByText('0-0 of 0')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('keeps the table after a failed payment update', async () => {
    signIn();
    let attempts = 0;
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'POST /payment': (config) => {
        attempts += 1;
        if (attempts === 1) {
          throw httpError(config, 400);
        }
        return {};
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('checkbox'));
    expect(
      await screen.findByText('Request failed. Please try again.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();

    await user.click(screen.getByRole('checkbox'));
    await waitFor(() =>
      expect(
        screen.queryByText('Request failed. Please try again.'),
      ).not.toBeInTheDocument(),
    );
    expect(attempts).toBe(2);
  });

  it('keeps the table after a failed delete', async () => {
    signIn();
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': () => page([submissionSet]),
      'GET /payment': () => page([]),
      'DELETE /submissionset/5': (config) => {
        throw httpError(config, 403, { detail: 'Forbidden' });
      },
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: 'Yes',
      }),
    );
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
  });

  it('keeps the table when a payments request for a left page fails', async () => {
    signIn();
    const sets = Array.from({ length: 21 }, (_, index) => ({
      ...submissionSet,
      id: index + 1,
    }));
    let failFirstPage: (() => void) | undefined;
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': (config) => {
        const pageNumber: number = config.params.page;
        const pageSize: number = config.params.page_size;
        return {
          ...page(
            sets.slice((pageNumber - 1) * pageSize, pageNumber * pageSize),
          ),
          count: sets.length,
        };
      },
      'GET /payment': (config) =>
        config.params.submission_set__in === '21'
          ? page<Payment>([
              {
                id: 8,
                created: '2026-01-01T00:00:00Z',
                modified: '2026-01-01T00:00:00Z',
                submission_set: 21,
                paid: true,
              },
            ])
          : new Promise((_resolve, reject) => {
              failFirstPage = () => reject(httpError(config, 400));
            }),
    });
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await waitFor(() => expect(failFirstPage).toBeDefined());

    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked());
    await act(async () => failFirstPage?.());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText('21-21 of 21')).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).toBeChecked();
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1);
  });

  it('keeps the payments of the shown page when a change on a left page finishes', async () => {
    signIn();
    const sets = Array.from({ length: 21 }, (_, index) => ({
      ...submissionSet,
      id: index + 1,
    }));
    let finishUpdate: (() => void) | undefined;
    const adapter = serveApi({
      'GET /contests/1': () => contest,
      'GET /submissionset': (config) => {
        const pageNumber: number = config.params.page;
        const pageSize: number = config.params.page_size;
        return {
          ...page(
            sets.slice((pageNumber - 1) * pageSize, pageNumber * pageSize),
          ),
          count: sets.length,
        };
      },
      'GET /payment': (config) =>
        page<Payment>(
          config.params.submission_set__in === '21'
            ? [
                {
                  id: 8,
                  created: '2026-01-01T00:00:00Z',
                  modified: '2026-01-01T00:00:00Z',
                  submission_set: 21,
                  paid: true,
                },
              ]
            : [],
        ),
      'POST /payment': () =>
        new Promise((resolve) => {
          finishUpdate = () => resolve({});
        }),
    });
    const paymentLoads = () =>
      adapter.mock.calls.filter(
        ([config]) => config.method === 'get' && config.url === '/payment',
      ).length;
    const user = userEvent.setup();
    open('/admin/contest/1/submissions');
    await waitFor(() => expect(paymentLoads()).toBe(1));
    const [firstPaid] = screen.getAllByRole('checkbox');
    if (!firstPaid) {
      throw new Error('The first page has no payment checkbox');
    }
    await user.click(firstPaid);
    await waitFor(() => expect(finishUpdate).toBeDefined());

    await user.click(screen.getByRole('button', { name: 'Go to next page' }));
    expect(await screen.findByText('21-21 of 21')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked());
    await act(async () => finishUpdate?.());
    await waitFor(() => expect(paymentLoads()).toBe(3));
    expect(screen.getByText('21-21 of 21')).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).toBeChecked();
  });
});
