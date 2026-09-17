import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import { apiClient } from './services/Base';
import { contest } from './test/fixtures';
import './i18n/config';
import App from './App';
import store from './store';
import { deleteMessage } from './store/notifications/actions';

function response(config: InternalAxiosRequestConfig, data: unknown) {
  return { config, data, status: 200, statusText: 'OK', headers: {} };
}
beforeEach(() => {
  localStorage.clear();
  for (const notification of store.getState().notifications) {
    store.dispatch(deleteMessage(notification.id));
  }
  apiClient.defaults.adapter = async (config) => {
    if (config.url === '/contest') {
      return response(config, {
        results: [contest],
        count: 1,
        next: null,
        previous: null,
      });
    }
    if (config.url === '/contest/1') {
      return response(config, { ...contest, dob_required: true });
    }
    if (config.url === '/user/login') {
      return response(config, {
        token: 'signed-in',
        expires: '2999-01-01T00:00:00Z',
      });
    }
    if (
      config.url === '/user/activate_account' ||
      config.url === '/user/password_reset'
    ) {
      return response(config, {});
    }
    throw new Error(`Unexpected request: ${config.url}`);
  };
});
function open(path: string) {
  window.history.replaceState(null, '', path);
  render(<App />);
}
describe('application routes', () => {
  it('loads the public contest list through the API', async () => {
    open('/contests');
    expect(
      await screen.findByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open' })).toHaveAttribute(
      'href',
      '/contest/1/upload',
    );
  });
  it('shows a useful empty state', async () => {
    apiClient.defaults.adapter = async (config) =>
      response(config, { results: [], count: 0, next: null, previous: null });
    open('/contests');
    expect(await screen.findByText('No active contests.')).toBeInTheDocument();
  });
  it('shows a failed list request', async () => {
    apiClient.defaults.adapter = async () => {
      throw new Error('Offline');
    };
    open('/contests');
    expect(
      await screen.findByText('Could not load contests. Please try again.'),
    ).toBeInTheDocument();
  });
  it('logs in and returns to the protected upload form', async () => {
    const user = userEvent.setup();
    open('/contest/1/upload');
    const email = await screen.findByRole('textbox', { name: /email/i });
    await user.type(email, 'participant@example.com');
    await user.type(screen.getByLabelText(/password/i), 'example-password');
    await user.click(screen.getByRole('button', { name: /log in|login/i }));
    await screen.findByRole('heading', { name: contest.title });
    await waitFor(() =>
      expect(window.location.pathname).toBe('/contest/1/upload'),
    );
    expect(
      await screen.findByRole('textbox', { name: /first name/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Nature' })).toBeInTheDocument();
    expect(screen.getAllByLabelText('Select photograph')).toHaveLength(2);
    expect(
      screen.getByRole('button', { name: /choose date/i }),
    ).toBeInTheDocument();
  });
  it('renders the requested confirmation template', async () => {
    localStorage.setItem(
      'token',
      JSON.stringify({ token: 'signed-in', expires: '2999-01-01T00:00:00Z' }),
    );
    open('/contest/1/confirm');
    expect(await screen.findByText('Submission received')).toBeInTheDocument();
  });
});
