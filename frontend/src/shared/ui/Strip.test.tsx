import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import Strip from './Strip';

describe('continuous', () => {
  it('is a progress bar with its range, value and name', () => {
    render(<Strip value={274} max={412} label="Scored 274 of 412" tick />);
    const strip = screen.getByRole('progressbar', {
      name: 'Scored 274 of 412',
    });
    expect(strip).toHaveAttribute('aria-valuemin', '0');
    expect(strip).toHaveAttribute('aria-valuemax', '412');
    expect(strip).toHaveAttribute('aria-valuenow', '274');
    expect(parseFloat(strip.style.getPropertyValue('--rl-value'))).toBeCloseTo(
      66.5,
      1,
    );
    expect(strip.querySelector('.rl-strip__tick')).not.toBeNull();
  });

  it('draws no head tick unless asked', () => {
    render(<Strip value={64} max={100} label="Uploading photo 05" />);
    const strip = screen.getByRole('progressbar', {
      name: 'Uploading photo 05',
    });
    expect(strip.style.getPropertyValue('--rl-value')).toBe('64%');
    expect(strip.querySelector('.rl-strip__tick')).toBeNull();
  });

  it.each([
    [-1, 10],
    [11, 10],
    [0, 0],
    [Number.NaN, 10],
  ])('refuses value %s of max %s', (value, max) => {
    expect(() =>
      render(<Strip value={value} max={max} label="Progress" />),
    ).toThrow();
  });
});

describe('segmented', () => {
  it('is an image named by its label, with the first segments filled', () => {
    render(<Strip segments={5} filled={3} label="Stage 3 of 5" />);
    const strip = screen.getByRole('img', { name: 'Stage 3 of 5' });
    const segments = strip.querySelectorAll('.rl-strip__seg');
    expect(segments).toHaveLength(5);
    expect(strip.querySelectorAll('.rl-strip__seg--on')).toHaveLength(3);
    expect(segments[2]).toHaveClass('rl-strip__seg--on');
    expect(segments[3]).not.toHaveClass('rl-strip__seg--on');
    expect(strip.style.getPropertyValue('--rl-segments')).toBe('5');
  });

  it('is hidden from assistive technology when decorative', () => {
    const { container } = render(
      <>
        <Strip segments={10} filled={6} segmentWidth={12} decorative />
        <span>6 of 10 photos</span>
      </>,
    );
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    const strip = container.querySelector('.rl-strip--segmented');
    expect(strip).toHaveAttribute('aria-hidden', 'true');
    expect(strip).not.toHaveAttribute('role');
    expect(strip).toHaveStyle({ '--rl-seg-width': '12px' });
  });

  it.each([
    [3, 4],
    [3, -1],
    [0, 0],
    [2.5, 1],
  ])('refuses %s segments with %s filled', (segments, filled) => {
    expect(() =>
      render(<Strip segments={segments} filled={filled} label="Stage" />),
    ).toThrow();
  });
});
