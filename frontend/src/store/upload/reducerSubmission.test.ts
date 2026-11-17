import { expect, it } from 'vitest';
import { SubmissionModel } from '../../types/models';
import { imageStore, submissionInit, submissionUpdate } from './actions';
import reducer from './reducerSubmission';
import { getEmptyImageError } from './utils';

// A submission with room for two photographs, as the upload form opens it.
const openSubmission = (isSeries: boolean): SubmissionModel =>
  reducer(
    undefined,
    submissionInit({
      id: 0,
      imageNumber: 2,
      isChanged: false,
      isNew: true,
      isSeries,
      titleRequired: false,
      descriptionRequired: false,
    }),
  );

const selectPhotograph = (submission: SubmissionModel): SubmissionModel =>
  reducer(
    submission,
    imageStore(2, 0, 0, {
      file: new File(['jpeg'], 'harbour.jpg', { type: 'image/jpeg' }),
      url: 'blob:harbour.jpg',
      errors: getEmptyImageError(),
    }),
  );

const type = (
  submission: SubmissionModel,
  name: 'title' | 'description',
  value: string,
): SubmissionModel =>
  reducer(submission, submissionUpdate(2, 0, { name, value }));

// The fields the form marks as required and validates as such.
const required = ({ meta }: SubmissionModel) => ({
  title: meta.titleRequired,
  description: meta.descriptionRequired,
});

it('keeps the title required when it is cleared with a photograph selected', () => {
  let submission = selectPhotograph(openSubmission(false));
  submission = type(submission, 'title', 'Harbour at dawn');
  submission = type(submission, 'title', '');

  expect(required(submission)).toEqual({ title: true, description: false });
});

it('keeps both texts of a series required when its description is cleared', () => {
  let submission = selectPhotograph(openSubmission(true));
  submission = type(submission, 'description', 'Boats leaving the harbour');
  submission = type(submission, 'description', '');

  expect(required(submission)).toEqual({ title: true, description: true });
});
