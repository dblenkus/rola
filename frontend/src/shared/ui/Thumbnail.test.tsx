import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import Thumbnail from './Thumbnail';
import ThumbnailGrid from './ThumbnailGrid';

it('shows the photo named by its alt text, loading lazily', () => {
  render(
    <Thumbnail src="/media/0275.jpg" alt="Morning above the fog" fit="cover" />,
  );
  const photo = screen.getByRole('img', { name: 'Morning above the fog' });
  expect(photo).toHaveAttribute('src', '/media/0275.jpg');
  expect(photo).toHaveAttribute('loading', 'lazy');
  expect(photo).toHaveAttribute('decoding', 'async');
  expect(photo.closest('.rl-thumb')).toHaveClass('rl-thumb--cover');
  expect(screen.queryByRole('figure')).not.toBeInTheDocument();
});

it('captions the photo with its ID as a figure', () => {
  render(
    <Thumbnail
      src="/media/0156.jpg"
      alt="Hiker on the ridge"
      fit="contain"
      caption="#0156"
      loading="eager"
      width={320}
      height={480}
    />,
  );
  const figure = screen.getByRole('figure');
  expect(figure).toHaveClass('rl-thumb--contain');
  expect(figure.querySelector('figcaption')).toHaveTextContent(/^#0156$/);
  const photo = screen.getByRole('img', { name: 'Hiker on the ridge' });
  expect(photo).toHaveAttribute('loading', 'eager');
  expect(photo).toHaveAttribute('width', '320');
  expect(photo).toHaveAttribute('height', '480');
});

it('names the empty well when there is no photo yet', () => {
  render(<Thumbnail label="Photo 03, not selected" fit="contain" size={64} />);
  const well = screen.getByRole('img', { name: 'Photo 03, not selected' });
  expect(well.tagName).toBe('DIV');
  expect(well.closest('.rl-thumb')).toHaveClass('rl-thumb--64');
});

it('lays thumbnails out in a grid that fits the page or the panel', () => {
  const { container, rerender } = render(
    <ThumbnailGrid>
      <Thumbnail src="/a.jpg" alt="A" fit="cover" />
      <Thumbnail src="/b.jpg" alt="B" fit="cover" />
    </ThumbnailGrid>,
  );
  const grid = container.firstElementChild;
  expect(grid).toHaveClass('rl-thumb-grid', 'ui-thumb-grid--page');
  expect(screen.getAllByRole('img')).toHaveLength(2);
  rerender(
    <ThumbnailGrid layout="panel">
      <Thumbnail src="/a.jpg" alt="A" fit="cover" />
    </ThumbnailGrid>,
  );
  expect(container.firstElementChild).toHaveClass('rl-thumb-grid');
  expect(container.firstElementChild).not.toHaveClass('ui-thumb-grid--page');
});
