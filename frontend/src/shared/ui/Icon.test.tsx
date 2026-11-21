import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import Icon from './Icon';

describe('icon', () => {
  it('is hidden from assistive technology without a label', () => {
    const { container } = render(<Icon name="lock" />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });

  it('is an image named by its label when it stands alone', () => {
    render(<Icon name="check" label="OK" />);
    const image = screen.getByRole('img', { name: 'OK' });
    expect(image).not.toHaveAttribute('aria-hidden');
  });

  it('draws the glyph on its grid in the colour of the text', () => {
    const { container } = render(<Icon name="user" />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('viewBox', '0 0 20 20');
    expect(svg).toHaveAttribute('width', '20');
    const group = container.querySelector('g');
    expect(group).toHaveAttribute('stroke', 'currentColor');
    expect(group).toHaveAttribute('fill', 'none');
    expect(group).toHaveAttribute('stroke-width', '1.5');
  });

  it.each(['monitor', 'sun', 'moon'] as const)(
    'draws the appearance glyph %s on the 16 px grid with a 1.5 px stroke',
    (name) => {
      const { container } = render(<Icon name={name} />);
      expect(container.querySelector('svg')).toHaveAttribute(
        'viewBox',
        '0 0 16 16',
      );
      expect(container.querySelector('g')).toHaveAttribute(
        'stroke-width',
        '1.5',
      );
    },
  );

  it('draws at the size it is given', () => {
    const { container } = render(<Icon name="arrow-up-right" size={16} />);
    expect(container.querySelector('svg')).toHaveAttribute('height', '16');
  });
});
