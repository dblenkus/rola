import { DateTime } from 'luxon';

import ImageService from '../services/ImageService';
import SubmissionService, {
  type SubmissionCreatePayload,
} from '../services/SubmissionService';
import AuthorService from '../services/AuthorService';
import type { ContestModel } from '../types/models';

// Photographs go up one at a time, so a failure stops the upload before
// any later file, the author or the submissions are created.
export default async function upload(contest: ContestModel): Promise<void> {
  const submissions: Omit<SubmissionCreatePayload, 'author'>[] = [];
  for (const theme of contest.themes) {
    for (const submission of theme.submissions) {
      const files = [];
      for (const image of submission.images) {
        if (image.file) {
          const { data } = await ImageService.uploadImage(image.file);
          files.push(data);
        }
      }
      if (files.length) {
        submissions.push({
          files,
          title: submission.title,
          description: submission.description,
          theme: theme.meta.id,
        });
      }
    }
  }
  if (!submissions.length) {
    throw new Error('Upload called without any photograph');
  }

  const { first_name, last_name, school, mentor, club, distinction, dob } =
    contest.author;
  const { data: author } = await AuthorService.create({
    first_name,
    last_name,
    dob: dob ? DateTime.fromJSDate(dob).toFormat('yyyy-MM-dd') : '',
    school: school ?? '',
    mentor: mentor ?? '',
    club: club ?? '',
    distinction,
  });
  await SubmissionService.createSubmissions(
    submissions.map((submission) => ({ ...submission, author })),
  );
}
