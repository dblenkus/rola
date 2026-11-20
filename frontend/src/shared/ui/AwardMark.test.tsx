import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import AwardMark from './AwardMark';

it('shows the award name as text beside a hidden ribbon', () => {
  const { container } = render(<AwardMark name="1. nagrada" />);
  const mark = container.firstElementChild;
  expect(mark).toHaveClass('rl-award', 'label');
  expect(mark).not.toHaveClass('rl-award--compact');
  expect(mark).toHaveTextContent(/^1\. nagrada$/);
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
});

it('keeps the name for screen readers in the compact form', () => {
  const { container } = render(
    <figcaption>
      #0275 <AwardMark name="Honourable mention" compact />
    </figcaption>,
  );
  expect(container.querySelector('.rl-award')).toHaveClass('rl-award--compact');
  expect(screen.getByText('Honourable mention')).toHaveClass('rl-award__name');
  expect(container.firstElementChild).toHaveTextContent(
    '#0275 Honourable mention',
  );
});
