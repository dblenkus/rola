import { DateTime } from 'luxon';

import ImageService from '../services/ImageService';
import SubmissionService, {
  type SubmissionCreatePayload,
} from '../services/SubmissionService';
import AuthorService from '../services/AuthorService';
import { loadToken, type Session } from '../services/token';
import type { ContestModel } from '../types/models';

// Another account signed in, or the session ended, during the upload.
export class SessionChanged extends Error {
  constructor() {
    super('The session changed during the upload');
    this.name = 'SessionChanged';
  }
}

// Photographs go up one at a time, so a failure stops the upload before
// any later file, the author or the submissions are created.
export default async function upload(
  contest: ContestModel,
  session: Session,
): Promise<void> {
  // Every request carries the token of the session that started the upload,
  // so none acts for an account that signs in meanwhile, in this tab or
  // another. The upload also stops once its account is no longer the one
  // signed in: a logout or another login ends its use of this browser.
  const authorization = `Token ${session.token}`;
  const checkSession = () => {
    if (loadToken()?.email !== session.email) {
      throw new SessionChanged();
    }
  };

  const submissions: Omit<SubmissionCreatePayload, 'author'>[] = [];
  for (const theme of contest.themes) {
    for (const submission of theme.submissions) {
      const files = [];
      for (const image of submission.images) {
        if (image.file) {
          checkSession();
          const { data } = await ImageService.uploadImage(
            image.file,
            authorization,
          );
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
  checkSession();
  const { data: author } = await AuthorService.create(
    {
      first_name,
      last_name,
      dob: dob ? DateTime.fromJSDate(dob).toFormat('yyyy-MM-dd') : '',
      school: school ?? '',
      mentor: mentor ?? '',
      club: club ?? '',
      distinction,
    },
    authorization,
  );
  checkSession();
  await SubmissionService.createSubmissions(
    submissions.map((submission) => ({ ...submission, author })),
    authorization,
  );
}
