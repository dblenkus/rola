import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';
import { apiClient } from '../../shared/api/client';
import { signIn } from '../../test/api';
import { open } from '../../test/app';

// Every request stays unanswered: these tests look at the shell only.
beforeEach(() => {
  localStorage.clear();
  apiClient.defaults.adapter = () => new Promise(() => {});
});

describe('standard layout', () => {
  it('has the banner, the main content and the footer', () => {
    open('/contests');
    const banner = screen.getByRole('banner');
    expect(
      within(banner).getByRole('link', { name: 'Rola, home' }),
    ).toHaveAttribute('href', '/');
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main');
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    expect(document.querySelector('.shell')).not.toHaveClass('shell--task');
  });

  it('skips from the first tab stop to the main content', async () => {
    const user = userEvent.setup();
    open('/contests');
    await user.tab();
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    expect(skip).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
  });

  it('has one main navigation, marking the current destination', () => {
    open('/results');
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
    const nav = screen.getByRole('navigation', { name: 'Main navigation' });
    expect(within(nav).getByRole('link', { name: 'Results' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    for (const name of ['Active contests', 'Edit submissions']) {
      expect(within(nav).getByRole('link', { name })).not.toHaveAttribute(
        'aria-current',
      );
    }
  });

  it('marks the upload form as a task screen with the same landmarks', () => {
    signIn();
    open('/contest/1/upload');
    expect(document.querySelector('.shell')).toHaveClass('shell--task');
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(
      screen.getByRole('navigation', { name: 'Main navigation' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });
});

describe('bare layout', () => {
  it('gives the rater the main content alone', async () => {
    const user = userEvent.setup();
    signIn();
    open('/judge/contest/1/theme/2/rate');
    expect(document.querySelector('.shell')).toHaveClass('shell--bare');
    expect(screen.queryByRole('banner')).not.toBeInTheDocument();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument();
    await user.tab();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('main')).toHaveFocus();
  });
});
