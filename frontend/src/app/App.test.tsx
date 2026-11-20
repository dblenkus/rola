import { screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import './i18n/config';
import { apiClient } from '../shared/api/client';
import store from './store';
import { deleteMessage } from '../features/notifications/state/actions';
import { httpError, page, serveApi, signIn } from '../test/api';
import { open } from '../test/app';
import { contest, jurySubmission } from '../test/fixtures';

beforeEach(() => {
  localStorage.clear();
  const notification = store.getState().notifications;
  if (notification) {
    store.dispatch(deleteMessage(notification.id));
  }
});

describe('failed page requests', () => {
  it.each([
    '/contest/1/upload',
    '/contest/1/confirm',
    '/user/submissions',
    '/judge',
    '/judge/contest/1/theme/2',
    '/judge/contest/1/theme/2/rate',
    '/judge/contest/1/theme/2/overview',
    '/admin/contest/1/submissions',
    '/admin/contest/1/submission/5',
    '/results/contest/1',
    '/results/contest/1/theme/2',
    '/results/contest/1/theme/2/submission/11',
  ])('shows a permission error instead of loading at %s', async (path) => {
    signIn();
    apiClient.defaults.adapter = async (config) => {
      throw httpError(config, 403, { detail: 'Forbidden' });
    };
    open(path);
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('shows a failed submission list after the contest loads', async () => {
    signIn();
    serveApi({
      'GET /contests/1': () => contest,
      'GET /submission-sets': (config) => {
        throw httpError(config, 403);
      },
    });
    open('/admin/contest/1/submissions');
    expect(
      await screen.findByText(
        'You do not have permission to perform this action.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: contest.title }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });
});
// jsdom lays nothing out, so these pin the structure the layout relies on.
// That the footer stays clear of the rater's photographs, at 1280x800 for
// example, is checked in a browser.
describe('page layout', () => {
  it('keeps the rater in the page flow at full width', async () => {
    serveApi({
      'GET /contests/1': () => contest,
      'GET /judge/submission': () =>
        page([jurySubmission(11, 'First photograph')]),
      'GET /rating': () => page([]),
    });
    signIn();
    open('/judge/contest/1/theme/2/rate?submission=11');
    const image = await screen.findByRole('img', { name: 'First photograph' });
    const main = screen.getByRole('main');
    expect(main).toContainElement(image);
    expect(screen.queryByRole('banner')).not.toBeInTheDocument();
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument();
    // An absolutely positioned rater takes no space, so the footer that
    // follows the container is drawn over it.
    const positions: string[] = [];
    for (
      let element = image.parentElement;
      element && element !== main;
      element = element.parentElement
    ) {
      positions.push(getComputedStyle(element).position);
    }
    expect(positions).not.toContain('absolute');
    expect(positions).not.toContain('fixed');
  });

  it('keeps other pages between the header and the footer', async () => {
    serveApi({ 'GET /contests': () => page([contest]) });
    open('/contests');
    const heading = await screen.findByRole('heading', { name: contest.title });
    expect(screen.getByRole('main')).toContainElement(heading);
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });

  // That no page scrolls sideways on a 360 or 390 pixel wide phone is
  // checked in a browser.
  it('puts the main navigation in the header and marks the current page', async () => {
    serveApi({ 'GET /contests': () => page([contest]) });
    open('/contests');
    await screen.findByRole('heading', { name: contest.title });
    const header = screen.getByRole('banner');
    const nav = within(header).getByRole('navigation', {
      name: 'Main navigation',
    });
    for (const name of ['Active contests', 'Edit submissions', 'Results']) {
      expect(within(nav).getByRole('link', { name })).toBeInTheDocument();
    }
    expect(
      within(nav).getByRole('link', { name: 'Active contests' }),
    ).toHaveAttribute('aria-current', 'page');
  });
});
