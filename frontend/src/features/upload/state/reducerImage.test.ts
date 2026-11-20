import { expect, it } from 'vitest';
import reducer, { imageInit, imageStore } from './reducerImage';
import { getEmptyImageError } from './utils';

const openSlot = () =>
  reducer(undefined, imageInit({ id: 0, isChanged: false, isNew: true }));

const harbour = new File(['jpeg'], 'harbour.jpg', { type: 'image/jpeg' });

it('keeps the pixel size of the photograph it stores', () => {
  const image = reducer(
    openSlot(),
    imageStore(2, 0, 0, {
      file: harbour,
      url: 'blob:harbour.jpg',
      errors: getEmptyImageError(),
      size: { width: 4000, height: 2667 },
    }),
  );

  expect(image.size).toEqual({ width: 4000, height: 2667 });
});

it('drops the pixel size with the photograph it was measured on', () => {
  const selected = reducer(
    openSlot(),
    imageStore(2, 0, 0, {
      file: harbour,
      url: 'blob:harbour.jpg',
      errors: getEmptyImageError(),
      size: { width: 4000, height: 2667 },
    }),
  );
  const removed = reducer(
    selected,
    imageStore(2, 0, 0, {
      file: undefined,
      url: '',
      errors: getEmptyImageError(),
    }),
  );

  expect(removed.size).toBeUndefined();
  expect(removed.file).toBeUndefined();
});
