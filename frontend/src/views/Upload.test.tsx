import { render, screen, waitFor } from '@testing-library/react';
import userEvent, { type UserEvent } from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../i18n/config';
import App from '../App';
import store from '../store';
import { deleteMessage } from '../store/notifications/actions';
import { httpError, page, serveApi, signIn } from '../test/api';
import { author, contest } from '../test/fixtures';
import type { Contest } from '../types/api';

const winter: Contest = { ...contest, id: 3, title: 'Winter photographs' };

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
    'GET /contest': () => page([contest, winter]),
    'GET /contest/1': () => contest,
    'GET /contest/3': () => winter,
    'POST /file': () => ({
      id: 21,
      created: '2026-01-01T00:00:00Z',
      modified: '2026-01-01T00:00:00Z',
      file: 'https://media.example/21.jpg',
    }),
    'POST /author': () => author,
    'POST /submission': () => [],
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

function open(path: string): void {
  window.history.replaceState(null, '', path);
  render(<App />);
}

beforeEach(() => {
  localStorage.clear();
  signIn();
  vi.stubGlobal('Image', DecodedImage);
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
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
      adapter.mock.calls.map(([config]) => `${config.method} ${config.url}`),
    ).toEqual([
      'get /contest/1',
      'post /file',
      'post /file',
      'post /author',
      'post /submission',
      'get /contest/1',
    ]);

    await user.click(screen.getByRole('link', { name: 'Active contests' }));
    const links = await screen.findAllByRole('link', { name: 'Open' });
    const winterLink = links.find(
      (link) => link.getAttribute('href') === '/contest/3/upload',
    );
    if (!winterLink) {
      throw new Error('The winter contest has no upload link');
    }
    await user.click(winterLink);
    expect(
      await screen.findByRole('heading', { name: winter.title }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/contest/3/upload');
  });

  it('stops at the first failed photograph and allows another try', async () => {
    const adapter = uploadApi({
      'POST /file': (config) => {
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
      'GET /contest/1': () => ({ ...contest, school_show: true }),
      'GET /institution': (config) => {
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
});
