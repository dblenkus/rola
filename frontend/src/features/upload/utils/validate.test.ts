import { beforeEach, expect, it, vi } from 'vitest';
import { createAppStore } from '../../../app/store';
import {
  authorUpdate,
  imageStore,
  submissionUpdate,
  uploadInit,
} from '../state/actions';
import { getEmptyImageError } from '../state/utils';
import { contest } from '../../../test/fixtures';
import { ContestModel } from '../models';
import imageReader from './imageReader';
import validate from './validate';

// jsdom cannot decode photographs; this one has a long edge the contest
// accepts.
vi.mock('./imageReader', () => ({ default: vi.fn() }));

beforeEach(() => {
  vi.mocked(imageReader).mockImplementation(async (file) => {
    const image = new Image(3000, 2000);
    image.src = `blob:${file.name}`;
    return image;
  });
});

// An upload form with everything else filled in: the entrant's names and
// one titled photograph, in a contest that shows the photo club field.
function filledForm(clubRequired: boolean, club: string): ContestModel {
  const store = createAppStore();
  store.dispatch(
    uploadInit(
      { ...contest, club_visible: true, club_required: clubRequired },
      'ana@example.com',
    ),
  );
  store.dispatch(authorUpdate({ name: 'first_name', value: 'Ana' }));
  store.dispatch(authorUpdate({ name: 'last_name', value: 'Novak' }));
  store.dispatch(authorUpdate({ name: 'club', value: club }));
  store.dispatch(
    imageStore(2, 0, 0, {
      file: new File(['jpeg'], 'harbour.jpg', { type: 'image/jpeg' }),
      url: 'blob:harbour.jpg',
      errors: getEmptyImageError(),
    }),
  );
  store.dispatch(
    submissionUpdate(2, 0, { name: 'title', value: 'Harbour at dawn' }),
  );
  return store.getState().upload.contest;
}

it('asks for the photo club when the contest requires it', async () => {
  const { author, errors } = await validate(filledForm(true, ''));

  expect(errors.hasError).toBe(true);
  expect(author.errors.club).toBe('Please enter the photo club.');
});

it('accepts a required photo club once it is entered', async () => {
  const { author, errors } = await validate(filledForm(true, 'Foto Ljubljana'));

  expect(author.errors.club).toBeNull();
  expect(errors.hasError).toBe(false);
});

it('accepts an empty photo club when the contest does not require it', async () => {
  const { author, errors } = await validate(filledForm(false, ''));

  expect(author.errors.club).toBeNull();
  expect(errors.hasError).toBe(false);
});
