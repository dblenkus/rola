import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent, { type UserEvent } from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../app/i18n/config';
import store from '../../../app/store';
import { deleteMessage } from '../../notifications';
import { uploadReset } from '../state/actions';
import {
  httpError,
  networkError,
  page,
  serveApi,
  signIn,
  withStatus,
} from '../../../test/api';
import { open } from '../../../test/app';
import { author, contest, submissionSet } from '../../../test/fixtures';
import type { Contest, Theme } from '../../../shared/api/types';

const winter: Contest = { ...contest, id: 3, title: 'Winter photographs' };

const alreadyReceived =
  'Your earlier upload had already been received. Check your entry under Edit submissions.';

// The server accepts only a UUID as an idempotency key.
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const storedPhotograph = {
  id: 21,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  file: 'https://media.example/21.jpg',
};

// jsdom does not decode images; validation only needs their dimensions.
class DecodedImage {
  width = 3000;
  height = 2000;
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  #src = '';

  get src(): string {
    return this.#src;
  }

  set src(value: string) {
    this.#src = value;
    queueMicrotask(() => this.onload?.());
  }
}

function photograph(name: string): File {
  return new File(['jpeg'], name, { type: 'image/jpeg' });
}

function uploadApi(overrides: Parameters<typeof serveApi>[0] = {}) {
  return serveApi({
    'GET /contests': () => page([contest, winter]),
    'GET /contests/1': () => contest,
    'GET /contests/3': () => winter,
    'POST /files': () => storedPhotograph,
    'POST /authors': () => author,
    'POST /submission-sets': () => withStatus(201, submissionSet),
    ...overrides,
  });
}

async function fillAuthor(user: UserEvent): Promise<void> {
  await user.type(
    await screen.findByRole('textbox', { name: /first name/i }),
    'Ana',
  );
  await user.type(screen.getByRole('textbox', { name: /last name/i }), 'Novak');
}

// Gives every submission of the form a photograph and a title.
async function fillSubmissions(user: UserEvent): Promise<void> {
  const inputs = screen.getAllByLabelText('Select photograph');
  const titles = screen.getAllByRole('textbox', { name: /title/i });
  for (const [index, input] of inputs.entries()) {
    await user.upload(input, photograph(`photo-${index}.jpg`));
  }
  for (const [index, title] of titles.entries()) {
    await user.type(title, `Photograph ${index}`);
  }
}

// Types a date into the date of birth's segments, which follow the English
// interface's day, month and year order.
async function typeDateOfBirth(user: UserEvent, digits: string): Promise<void> {
  const group = await screen.findByRole('group', { name: 'Date of birth' });
  const [day] = within(group).getAllByRole('spinbutton');
  if (!day) {
    throw new Error('The date of birth has no segments');
  }
  await user.click(day);
  await user.keyboard(digits);
}

// A response settles through promise callbacks only, so one macrotask later
// it has reached the view, whether the view uses it or not.
async function settle(): Promise<void> {
  await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
}

async function openFromContestList(
  user: UserEvent,
  contestId: number,
): Promise<void> {
  await user.click(screen.getByRole('link', { name: 'Active contests' }));
  const links = await screen.findAllByRole('link', { name: 'Open' });
  const link = links.find(
    (candidate) =>
      candidate.getAttribute('href') === `/contest/${contestId}/upload`,
  );
  if (!link) {
    throw new Error(`Contest ${contestId} has no upload link`);
  }
  await user.click(link);
}

beforeEach(() => {
  localStorage.clear();
  signIn();
  vi.stubGlobal('Image', DecodedImage);
  // The store outlives each test; start every test with a fresh form.
  store.dispatch(uploadReset());
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('photograph upload', () => {
  it('opens the next upload form after a completed upload', async () => {
    const adapter = uploadApi();
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/confirm');
    expect(
      screen.getByText(`Your photographs for ${contest.title} were uploaded.`),
    ).toBeInTheDocument();
    expect(screen.queryByText(alreadyReceived)).not.toBeInTheDocument();
    expect(
      adapter.mock.calls.map(([config]) => `${config.method} ${config.url}`),
    ).toEqual([
      'get /contests/1',
      'post /files',
      'post /files',
      'post /authors',
      'post /submission-sets',
      'get /contests/1',
    ]);

    await openFromContestList(user, 3);
    expect(
      await screen.findByRole('heading', { name: winter.title }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/3/upload');
  });

  it('enters the photographs as one submission set of the author', async () => {
    const nature = contest.themes[0];
    if (!nature) {
      throw new Error('The contest fixture has no theme');
    }
    const cities: Theme = {
      ...nature,
      id: 6,
      title: 'Cities',
      is_series: true,
      max_photos: 2,
    };
    let photographId = 40;
    let body: unknown;
    uploadApi({
      'GET /contests/1': () => ({ ...contest, themes: [nature, cities] }),
      'POST /files': () => {
        photographId += 1;
        return withStatus(201, { ...storedPhotograph, id: photographId });
      },
      'POST /authors': () => withStatus(201, author),
      'POST /submission-sets': (config) => {
        body = JSON.parse(String(config.data));
        return withStatus(201, submissionSet);
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    // Nature takes one photograph per submission and Cities is a series of
    // two; the second Nature submission stays empty.
    const [dawn, , street, square] =
      await screen.findAllByLabelText('Select photograph');
    const [dawnTitle, , citiesTitle] = screen.getAllByRole('textbox', {
      name: /title/i,
    });
    // Only a series has a description.
    const [citiesDescription] = screen.getAllByRole('textbox', {
      name: /description/i,
    });
    if (
      !dawn ||
      !street ||
      !square ||
      !dawnTitle ||
      !citiesTitle ||
      !citiesDescription
    ) {
      throw new Error('The form lacks a field of the two themes');
    }
    await user.upload(dawn, photograph('dawn.jpg'));
    await user.upload(street, photograph('street.jpg'));
    await user.upload(square, photograph('square.jpg'));
    await user.type(dawnTitle, 'Dawn');
    await user.type(citiesTitle, 'Old town');
    await user.type(citiesDescription, 'A walk');
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(body).toEqual({
      author: author.id,
      submissions: [
        { theme: nature.id, title: 'Dawn', description: '', files: [41] },
        {
          theme: cities.id,
          title: 'Old town',
          description: 'A walk',
          files: [42, 43],
        },
      ],
    });
  });

  it('completes an upload the server had already received', async () => {
    uploadApi({
      'POST /submission-sets': () => withStatus(200, submissionSet),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/confirm');
    expect(screen.getByText(alreadyReceived)).toBeInTheDocument();
    expect(
      screen.queryByText('Upload failed. Please try again.'),
    ).not.toBeInTheDocument();
  });

  it('says so when a retry finds the earlier upload already received', async () => {
    let attempts = 0;
    uploadApi({
      'POST /submission-sets': (config) => {
        attempts += 1;
        // The server stored the first request, but its response was lost.
        if (attempts === 1) {
          throw networkError(config);
        }
        return withStatus(200, submissionSet);
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Upload failed. Please try again.'),
    ).toBeInTheDocument();
    const [title] = screen.getAllByRole('textbox', { name: /title/i });
    if (!title) {
      throw new Error('The form has no title field');
    }
    await user.type(title, ' corrected');
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(screen.getByText(alreadyReceived)).toBeInTheDocument();
  });

  it('stops at the first failed photograph and allows another try', async () => {
    const adapter = uploadApi({
      'POST /files': (config) => {
        throw httpError(config, 400, { detail: 'Invalid image.' });
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Upload failed. Please try again.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Upload' })).toBeEnabled();
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'post'),
    ).toHaveLength(1);
  });

  it('sends the same key when retrying after a lost response', async () => {
    const submissionKeys: unknown[] = [];
    uploadApi({
      'POST /submission-sets': (config) => {
        submissionKeys.push(config.headers.get('Idempotency-Key'));
        if (submissionKeys.length === 1) {
          throw networkError(config);
        }
        return withStatus(201, submissionSet);
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Upload failed. Please try again.'),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/confirm');
    const [lost, retried] = submissionKeys;
    expect(lost).toMatch(uuid);
    expect(retried).toBe(lost);

    await openFromContestList(user, 1);
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(submissionKeys).toHaveLength(3);
    expect(submissionKeys[2]).toMatch(uuid);
    expect(submissionKeys[2]).not.toBe(lost);
  });

  it('explains an upload refused because the contest closed', async () => {
    uploadApi({
      'POST /submission-sets': (config) => {
        throw httpError(config, 403, {
          detail: 'This contest is not accepting entries.',
        });
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText(
        'The contest is closed. Your photographs were not submitted.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Upload failed. Please try again.'),
    ).not.toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/upload');
  });

  it('asks for a photograph before sending anything', async () => {
    const adapter = uploadApi();
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Select at least one image.'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Please fix errors before uploading.'),
    ).toBeInTheDocument();
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'post'),
    ).toHaveLength(0);
  });

  it('shows a failed institution lookup', async () => {
    uploadApi({
      'GET /contests/1': () => ({ ...contest, school_visible: true }),
      'GET /institutions': (config) => {
        throw httpError(config, 503);
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await user.click(await screen.findByRole('combobox', { name: 'School' }));
    expect(
      await screen.findByText('Could not load institutions.'),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('progressbar')).not.toBeInTheDocument(),
    );
  });

  it('keeps the entered form when the session expires during an upload', async () => {
    uploadApi({
      'POST /files': (config) => {
        throw httpError(config, 401);
      },
      'POST /tokens': () =>
        withStatus(201, {
          token: 'renewed',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('Ana');
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.getByRole('textbox', { name: /last name/i })).toHaveValue(
      'Novak',
    );
    expect(screen.getByDisplayValue('Photograph 0')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Photograph 1')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Change' })).toHaveLength(2);
  });

  it('keeps the entered form when the session expires while it is filled in', async () => {
    const now = Date.now();
    localStorage.setItem(
      'token',
      JSON.stringify({
        token: 'expiring',
        expires: new Date(now + 60_000).toISOString(),
        email: 'ana@example.com',
      }),
    );
    uploadApi({
      'POST /files': (config) => {
        throw httpError(config, 401);
      },
      'POST /tokens': () =>
        withStatus(201, {
          token: 'renewed',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    vi.spyOn(Date, 'now').mockReturnValue(now + 120_000);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('Ana');
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.getByDisplayValue('Photograph 0')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Change' })).toHaveLength(2);
  });

  it('asks for a new login before uploading with less than an hour left', async () => {
    localStorage.setItem(
      'token',
      JSON.stringify({
        token: 'expiring',
        expires: new Date(Date.now() + 30 * 60_000).toISOString(),
        email: 'ana@example.com',
      }),
    );
    const adapter = uploadApi({
      'POST /tokens': () =>
        withStatus(201, {
          token: 'renewed',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText(
        'Your session is about to expire. Please log in again.',
      ),
    ).toBeInTheDocument();
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'ana@example.com',
    );
    expect(window.location.pathname).toBe('/login');
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'post'),
    ).toHaveLength(0);

    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('Ana');
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.getByDisplayValue('Photograph 0')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Photograph 1')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/confirm');
  });

  it('starts an empty form when another account logs in after a rejected session', async () => {
    uploadApi({
      'POST /files': (config) => {
        throw httpError(config, 401);
      },
      'POST /tokens': () =>
        withStatus(201, {
          token: 'next-account',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'next@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('');
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.queryByDisplayValue('Photograph 0')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Change' }),
    ).not.toBeInTheDocument();
  });

  it('starts an empty form when another account signs in from another tab', async () => {
    const adapter = uploadApi();
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    act(() => {
      signIn('next-account', 'next@example.com');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token' }));
    });
    expect(screen.queryByDisplayValue('Ana')).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue('Photograph 0')).not.toBeInTheDocument();
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('');
    expect(
      screen.queryByRole('button', { name: 'Change' }),
    ).not.toBeInTheDocument();
    expect(
      adapter.mock.calls.filter(([config]) => config.method === 'post'),
    ).toHaveLength(0);
  });

  it('sends no request as an account that signed in during an upload', async () => {
    const photographResponses: (() => void)[] = [];
    const adapter = uploadApi({
      'POST /files': () =>
        photographResponses.length
          ? storedPhotograph
          : new Promise((resolve) =>
              photographResponses.push(() => resolve(storedPhotograph)),
            ),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(photographResponses).toHaveLength(1));
    act(() => {
      signIn('next-account', 'next@example.com');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token' }));
    });
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('');

    photographResponses[0]?.();
    await settle();
    expect(
      adapter.mock.calls
        .map(([config]) => config)
        .filter((config) => config.method === 'post')
        .map((config) => [config.url, config.headers.get('Authorization')]),
    ).toEqual([['/files', 'Bearer signed-in']]);
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      '',
    );
    expect(
      screen.queryByText('Upload failed. Please try again.'),
    ).not.toBeInTheDocument();
  });

  it('starts an empty form after a completed upload', async () => {
    uploadApi();
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    await openFromContestList(user, 1);
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('');
    expect(screen.queryByDisplayValue('Photograph 0')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Change' }),
    ).not.toBeInTheDocument();
  });

  it('starts an empty form for the next account after a logout', async () => {
    uploadApi({
      'DELETE /tokens/current': () => withStatus(204, ''),
      'POST /tokens': () =>
        withStatus(201, {
          token: 'next-account',
          expires: '2999-01-01T00:00:00Z',
        }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(
      screen.getByRole('button', { name: 'account of current user' }),
    );
    await user.click(screen.getByRole('menuitem', { name: 'Logout' }));
    await user.type(
      await screen.findByRole('textbox', { name: /email/i }),
      'next@example.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: 'Login' }));
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('');
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.getByRole('textbox', { name: /last name/i })).toHaveValue('');
    expect(screen.queryByDisplayValue('Photograph 0')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Change' }),
    ).not.toBeInTheDocument();
  });

  it('shows no form until the next contest loads', async () => {
    const winterResponses: (() => void)[] = [];
    uploadApi({
      'GET /contests/3': () =>
        new Promise((resolve) => winterResponses.push(() => resolve(winter))),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    await openFromContestList(user, 3);
    await waitFor(() => expect(winterResponses).toHaveLength(1));
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(
      screen.queryByRole('textbox', { name: /first name/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Upload' }),
    ).not.toBeInTheDocument();

    winterResponses[0]?.();
    expect(
      await screen.findByRole('heading', { name: winter.title }),
    ).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      '',
    );
  });

  it('starts an empty form for another contest', async () => {
    uploadApi();
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await openFromContestList(user, 3);
    expect(
      await screen.findByRole('heading', { name: winter.title }),
    ).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      '',
    );
  });

  it('stays on another page when an upload finishes there', async () => {
    const submissionResponses: (() => void)[] = [];
    uploadApi({
      'POST /submission-sets': () =>
        new Promise((resolve) =>
          submissionResponses.push(() =>
            resolve(withStatus(201, submissionSet)),
          ),
        ),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(submissionResponses).toHaveLength(1));
    await user.click(screen.getByRole('link', { name: 'Results' }));

    submissionResponses[0]?.();
    await settle();
    expect(window.location.pathname).toBe('/results');
    expect(
      screen.queryByText('Thank you for uploading photos!'),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(`Your photographs for ${contest.title} were uploaded.`),
    ).toBeInTheDocument();
  });

  it("keeps another contest's form when an earlier upload finishes", async () => {
    const submissionResponses: (() => void)[] = [];
    uploadApi({
      'POST /submission-sets': () =>
        new Promise((resolve) =>
          submissionResponses.push(() =>
            resolve(withStatus(201, submissionSet)),
          ),
        ),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(submissionResponses).toHaveLength(1));
    await openFromContestList(user, 3);
    await user.type(
      await screen.findByRole('textbox', { name: /first name/i }),
      'Mia',
    );

    submissionResponses[0]?.();
    await settle();
    expect(window.location.pathname).toBe('/contest/3/upload');
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      'Mia',
    );
    expect(
      screen.getByText(`Your photographs for ${contest.title} were uploaded.`),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('stays on the next contest while it loads when an earlier upload finishes', async () => {
    const submissionResponses: (() => void)[] = [];
    const winterResponses: (() => void)[] = [];
    uploadApi({
      'POST /submission-sets': () =>
        new Promise((resolve) =>
          submissionResponses.push(() =>
            resolve(withStatus(201, submissionSet)),
          ),
        ),
      'GET /contests/3': () =>
        new Promise((resolve) => winterResponses.push(() => resolve(winter))),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(submissionResponses).toHaveLength(1));
    await openFromContestList(user, 3);
    await waitFor(() => expect(winterResponses).toHaveLength(1));

    submissionResponses[0]?.();
    await settle();
    expect(window.location.pathname).toBe('/contest/3/upload');
    expect(
      screen.queryByText('Thank you for uploading photos!'),
    ).not.toBeInTheDocument();

    winterResponses[0]?.();
    expect(
      await screen.findByRole('heading', { name: winter.title }),
    ).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      '',
    );
  });

  it('confirms the upload in a form reopened during it', async () => {
    const submissionResponses: (() => void)[] = [];
    uploadApi({
      'POST /submission-sets': () =>
        new Promise((resolve) =>
          submissionResponses.push(() =>
            resolve(withStatus(201, submissionSet)),
          ),
        ),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(submissionResponses).toHaveLength(1));
    await openFromContestList(user, 1);
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toHaveValue('Ana');

    submissionResponses[0]?.();
    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/1/confirm');
  });

  it("keeps the next contest's form when an earlier contest loads late", async () => {
    const contestResponses: (() => void)[] = [];
    uploadApi({
      'GET /contests/1': () =>
        new Promise((resolve) => contestResponses.push(() => resolve(contest))),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await waitFor(() => expect(contestResponses).toHaveLength(1));
    await openFromContestList(user, 3);
    await user.type(
      await screen.findByRole('textbox', { name: /first name/i }),
      'Mia',
    );

    contestResponses[0]?.();
    await settle();
    expect(window.location.pathname).toBe('/contest/3/upload');
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      'Mia',
    );
  });

  it("keeps the next account's form when the previous account's contest loads late", async () => {
    const contestResponses: (() => void)[] = [];
    uploadApi({
      'GET /contests/1': () =>
        new Promise((resolve) => contestResponses.push(() => resolve(contest))),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await waitFor(() => expect(contestResponses).toHaveLength(1));
    act(() => {
      signIn('next-account', 'next@example.com');
      window.dispatchEvent(new StorageEvent('storage', { key: 'token' }));
    });
    await waitFor(() => expect(contestResponses).toHaveLength(2));
    contestResponses[1]?.();
    await user.type(
      await screen.findByRole('textbox', { name: /first name/i }),
      'Mia',
    );

    contestResponses[0]?.();
    await settle();
    expect(window.location.pathname).toBe('/contest/1/upload');
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      'Mia',
    );
  });

  it("shows a contest's changed themes and required fields in a kept form", async () => {
    let current = contest;
    uploadApi({ 'GET /contests/1': () => current });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await fillSubmissions(user);
    expect(
      screen.queryByRole('combobox', { name: 'School' }),
    ).not.toBeInTheDocument();
    const cities: Theme = {
      id: 5,
      created: '2026-01-01T00:00:00Z',
      modified: '2026-01-01T00:00:00Z',
      title: 'Cities',
      is_series: false,
      max_photos: 1,
    };
    current = {
      ...contest,
      themes: [
        ...contest.themes.map((theme) => ({
          ...theme,
          title: 'Nature and parks',
        })),
        cities,
      ],
      school_visible: true,
      school_required: true,
    };

    await openFromContestList(user, 1);
    expect(
      await screen.findByRole('heading', { name: 'Cities' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Nature and parks' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'School' })).toBeRequired();
    expect(screen.getByRole('textbox', { name: /first name/i })).toHaveValue(
      'Ana',
    );
    expect(screen.getByDisplayValue('Photograph 0')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Photograph 1')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Change' })).toHaveLength(2);
    expect(screen.getAllByLabelText('Select photograph')).toHaveLength(3);
  });
  it('sends the typed date of birth with the author', async () => {
    const authors: unknown[] = [];
    uploadApi({
      'GET /contests/1': () => ({ ...contest, date_of_birth_required: true }),
      'POST /authors': (config) => {
        authors.push(JSON.parse(String(config.data)));
        return author;
      },
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await typeDateOfBirth(user, '07032010');
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(
      await screen.findByText('Thank you for uploading photos!'),
    ).toBeInTheDocument();
    expect(authors).toEqual([
      expect.objectContaining({ date_of_birth: '2010-03-07' }),
    ]);
  });

  it('asks again for a required date of birth whose year was cut short', async () => {
    const adapter = uploadApi({
      'GET /contests/1': () => ({ ...contest, date_of_birth_required: true }),
    });
    const user = userEvent.setup();
    open('/contest/1/upload');
    await fillAuthor(user);
    await typeDateOfBirth(user, '07032010');
    const group = screen.getByRole('group', { name: 'Date of birth' });
    const year = within(group).getAllByRole('spinbutton').at(-1);
    if (!year) {
      throw new Error('The date of birth has no year');
    }
    await user.click(year);
    await user.keyboard('201');
    await fillSubmissions(user);
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(
      await screen.findByRole('group', {
        name: 'Date of birth',
        // React Aria adds its own description of the segments' state.
        description: /Please enter the date of birth\./,
      }),
    ).toBeInTheDocument();
    expect(
      adapter.mock.calls.map(([config]) => `${config.method} ${config.url}`),
    ).toEqual(['get /contests/1']);
  });
});
