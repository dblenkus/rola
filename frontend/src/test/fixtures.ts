import type { Author, Contest, Submission, SubmissionSet } from '../types/api';

export const contest: Contest = {
  id: 1,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  title: 'Autumn photographs',
  description: 'Share your photographs.',
  themes: [
    {
      id: 2,
      created: '2026-01-01T00:00:00Z',
      modified: '2026-01-01T00:00:00Z',
      title: 'Nature',
      is_series: false,
      n_photos: 2,
      submissions_number: 0,
    },
  ],
  start_date: '2026-01-01',
  end_date: '2026-12-31',
  notice_html: '<p>Contest instructions</p>',
  confirmation_html: '<p>Submission received</p>',
  header_image: null,
  dob_required: false,
  club_show: false,
  club_required: false,
  school_show: false,
  school_required: false,
};

export const author: Author = {
  id: 4,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  first_name: 'Ana',
  last_name: 'Novak',
  email: null,
};

export function submission(id: number, title: string): Submission {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    author,
    theme: 2,
    title,
    files: [
      {
        id,
        created: '2026-01-01T00:00:00Z',
        modified: '2026-01-01T00:00:00Z',
        file: `https://media.example/${id}.jpg`,
      },
    ],
  };
}

export const submissionSet: SubmissionSet = {
  id: 5,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  submissions: [submission(11, 'Autumn trees')],
  author,
  contest: 1,
};
