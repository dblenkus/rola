import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import NoticeHtml from './NoticeHtml';

it('keeps notice formatting and removes executable markup', () => {
  const { container } = render(
    <NoticeHtml
      notice={
        '<strong>Instructions</strong><script>alert(1)</script><img src="x" onerror="alert(2)">'
      }
    />,
  );
  expect(screen.getByText('Instructions').tagName).toBe('STRONG');
  expect(container.querySelector('script')).toBeNull();
  expect(container.querySelector('img')).not.toHaveAttribute('onerror');
});

it('opens notice links in a new tab without giving them the opener', () => {
  render(
    <NoticeHtml
      notice={
        '<a href="https://example.com/rules.pdf" target="_blank" rel="opener">Rules</a> <a href="https://example.com/">Home</a>'
      }
    />,
  );
  const rules = screen.getByRole('link', { name: 'Rules' });
  expect(rules).toHaveAttribute('target', '_blank');
  expect(rules).toHaveAttribute('rel', 'noopener noreferrer');
  expect(screen.getByRole('link', { name: 'Home' })).not.toHaveAttribute('rel');
});
