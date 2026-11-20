import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import SanitizedHtml from './SanitizedHtml';

it('keeps formatting and removes executable markup', () => {
  const { container } = render(
    <SanitizedHtml
      html={
        '<strong>Instructions</strong><script>alert(1)</script><img src="x" onerror="alert(2)">'
      }
    />,
  );
  expect(screen.getByText('Instructions').tagName).toBe('STRONG');
  expect(container.querySelector('script')).toBeNull();
  expect(container.querySelector('img')).not.toHaveAttribute('onerror');
});

it('opens links in a new tab without giving them the opener', () => {
  render(
    <SanitizedHtml
      html={
        '<a href="https://example.com/rules.pdf" target="_blank" rel="opener">Rules</a> <a href="https://example.com/">Home</a>'
      }
    />,
  );
  const rules = screen.getByRole('link', { name: 'Rules' });
  expect(rules).toHaveAttribute('target', '_blank');
  expect(rules).toHaveAttribute('rel', 'noopener noreferrer');
  expect(screen.getByRole('link', { name: 'Home' })).not.toHaveAttribute('rel');
});
