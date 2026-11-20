import {
  authorizationHeader,
  loadToken,
  type Session,
} from '../../../shared/api/token';
import type { ContestModel } from '../models';
import {
  createAuthor,
  createSubmissionSet,
  uploadImage,
  type SubmissionSetCreatePayload,
} from '../api';

// Another account signed in, or the session ended, during the upload.
export class SessionChanged extends Error {
  constructor() {
    super('The session changed during the upload');
    this.name = 'SessionChanged';
  }
}

// The day as the API takes it, "2010-03-07", from the date's local calendar
// fields: the date picker gives local midnight, which an ISO string in UTC
// would move to the day before east of Greenwich.
export function apiDate(date: Date): string {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

// Photographs go up one at a time, so a failure stops the upload before
// any later file, the author or the submission set are created. A retry
// sends the photographs and the author again, but the form's upload key keeps
// the submission set from being stored twice. Resolves to whether the server had
// already stored them, in which case this request changed nothing.
export default async function upload(
  contest: ContestModel,
  session: Session,
  uploadKey: string,
): Promise<boolean> {
  // Every request carries the token of the session that started the upload,
  // so none acts for an account that signs in meanwhile, in this tab or
  // another. The upload also stops once its account is no longer the one
  // signed in: a logout or another login ends its use of this browser.
  const authorization = authorizationHeader(session.token);
  const checkSession = () => {
    if (loadToken()?.email !== session.email) {
      throw new SessionChanged();
    }
  };

  const submissions: SubmissionSetCreatePayload['submissions'] = [];
  for (const theme of contest.themes) {
    for (const submission of theme.submissions) {
      const files = [];
      for (const image of submission.images) {
        if (image.file) {
          checkSession();
          const { data } = await uploadImage(image.file, authorization);
          files.push(data.id);
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

  const {
    first_name,
    last_name,
    school,
    mentor,
    club,
    distinction,
    date_of_birth,
  } = contest.author;
  checkSession();
  const { data: author } = await createAuthor(
    {
      first_name,
      last_name,
      date_of_birth: date_of_birth ? apiDate(date_of_birth) : '',
      school: school ?? '',
      mentor: mentor ?? '',
      club: club ?? '',
      distinction,
    },
    authorization,
  );
  checkSession();
  const { status } = await createSubmissionSet(
    { author: author.id, submissions },
    uploadKey,
    authorization,
  );
  return status === 200;
}
