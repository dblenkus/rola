import { beforeEach, expect, it, vi } from 'vitest';
import { createAppStore } from '../../app/store';
import { contest } from '../../test/fixtures';
import imageReader from '../../utils/imageReader';
import { imageUpdate, uploadInit, uploadReset } from './actions';

// Decoding a photograph takes a while in the browser; each test finishes
// the reads itself, in the order it needs.
vi.mock('../../utils/imageReader', () => ({ default: vi.fn() }));

let reads: Map<File, () => void>;

beforeEach(() => {
  reads = new Map();
  vi.mocked(imageReader).mockImplementation(
    (file) =>
      new Promise((resolve) => {
        reads.set(file, () => resolve(decoded(file)));
      }),
  );
});

function decoded(file: File): HTMLImageElement {
  const image = new Image();
  image.src = `blob:${file.name}`;
  return image;
}

function finishRead(file: File): void {
  const finish = reads.get(file);
  if (!finish) {
    throw new Error(`${file.name} is not being read`);
  }
  finish();
}

function openForm() {
  const store = createAppStore();
  store.dispatch(uploadInit(contest, 'ana@example.com'));
  return store;
}

type Store = ReturnType<typeof openForm>;

// The first photograph of the contest's only theme.
const select = (store: Store, file: File | undefined) =>
  store.dispatch(imageUpdate(2, 0, 0, { file }));

// The photograph a slot holds, by name, and its preview.
const chosen = (store: Store) => {
  const { file, url } =
    store.getState().upload.contest.themes[0]!.submissions[0]!.images[0]!;
  return { name: file?.name, url };
};

// The error the field shows under that photograph.
const imageErrors = (store: Store) =>
  store.getState().upload.contest.themes[0]!.submissions[0]!.images[0]!.errors;

const photograph = (name: string) =>
  new File(['jpeg'], name, { type: 'image/jpeg' });

// The browser fails to decode the next photograph read, as it does for
// HEIC data saved as .jpg.
const failNextRead = () =>
  vi
    .mocked(imageReader)
    .mockRejectedValueOnce(new DOMException('Problem reading input file.'));

it('reports a photograph the browser cannot read', async () => {
  const store = openForm();
  const readable = photograph('readable.jpg');
  const reading = select(store, readable);
  finishRead(readable);
  await reading;

  failNextRead();
  await expect(
    select(store, photograph('broken.jpg')),
  ).resolves.toBeUndefined();

  expect(chosen(store)).toEqual({ name: 'broken.jpg', url: '' });
  expect(imageErrors(store)).toEqual({
    file: 'Invalid file.',
    hasError: true,
  });
});

it('drops the read error when the photograph is replaced or removed', async () => {
  const store = openForm();
  failNextRead();
  await select(store, photograph('broken.jpg'));
  const readable = photograph('readable.jpg');
  const reading = select(store, readable);
  finishRead(readable);
  await reading;
  expect(chosen(store)).toEqual({
    name: 'readable.jpg',
    url: 'blob:readable.jpg',
  });
  expect(imageErrors(store)).toEqual({ file: null, hasError: false });

  failNextRead();
  await select(store, photograph('broken.jpg'));
  await select(store, undefined);
  expect(chosen(store)).toEqual({ name: undefined, url: '' });
  expect(imageErrors(store)).toEqual({ file: null, hasError: false });
});

it('leaves a photograph removed during its read out of the form', async () => {
  const store = openForm();
  const first = photograph('first.jpg');
  const reading = select(store, first);
  finishRead(first);
  await reading;
  expect(chosen(store)).toEqual({ name: 'first.jpg', url: 'blob:first.jpg' });

  const replacement = photograph('replacement.jpg');
  const replacing = select(store, replacement);
  await select(store, undefined);
  finishRead(replacement);
  await replacing;

  expect(chosen(store)).toEqual({ name: undefined, url: '' });
});

it('keeps the latest photograph when an earlier choice is read last', async () => {
  const store = openForm();
  const large = photograph('large.jpg');
  const small = photograph('small.jpg');
  const readingLarge = select(store, large);
  const readingSmall = select(store, small);
  finishRead(small);
  await readingSmall;
  finishRead(large);
  await readingLarge;

  expect(chosen(store)).toEqual({ name: 'small.jpg', url: 'blob:small.jpg' });
});

it('leaves a new form alone when a read for the previous one finishes', async () => {
  const store = openForm();
  const previous = photograph('previous.jpg');
  const reading = select(store, previous);
  store.dispatch(uploadReset());
  store.dispatch(uploadInit(contest, 'ana@example.com'));
  finishRead(previous);
  await reading;

  expect(chosen(store)).toEqual({ name: undefined, url: '' });
});
