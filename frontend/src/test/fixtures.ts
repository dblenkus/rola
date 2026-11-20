import type {
  Author,
  Contest,
  Image,
  JurySubmission,
  Rating,
  Submission,
  SubmissionSet,
  Theme,
} from '../shared/api/types';

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

// The contest with its theme changed, as a series theme or a renamed one.
export function contestWithTheme(changes: Partial<Theme>): Contest {
  return {
    ...contest,
    themes: contest.themes.map((theme) => ({ ...theme, ...changes })),
  };
}

export const author: Author = {
  id: 4,
  created: '2026-01-01T00:00:00Z',
  modified: '2026-01-01T00:00:00Z',
  first_name: 'Ana',
  last_name: 'Novak',
  email: null,
};

function photograph(id: number): Image {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    file: `https://media.example/${id}.jpg`,
  };
}

export function submission(id: number, title: string): Submission {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    author,
    theme: 2,
    title,
    files: [photograph(id)],
  };
}

export function jurySubmission(id: number, title: string): JurySubmission {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    theme: 2,
    title,
    description: null,
    files: [photograph(id)],
  };
}

// A judge's score for a submission, under its own id.
export function rating(
  id: number,
  submissionId: number,
  value: number,
): Rating {
  return {
    id,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    submission: submissionId,
    rating: value,
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

// An instant as the API sends a date-time, such as a contest's `end_date`:
// with the local zone's offset ("2026-12-07T23:59:59+01:00"), or in UTC
// ("2026-12-07T22:59:59.000Z"), which near midnight falls on another
// calendar day than the local one.
export function apiDateTime(date: Date, form: 'offset' | 'utc'): string {
  if (form === 'utc') return date.toISOString();
  const pad = (value: number) => String(value).padStart(2, '0');
  const offset = -date.getTimezoneOffset();
  const sign = offset < 0 ? '-' : '+';
  const hours = pad(Math.floor(Math.abs(offset) / 60));
  const minutes = pad(Math.abs(offset) % 60);
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` +
    `${sign}${hours}:${minutes}`
  );
}
