import { ResultsSubmission } from '../../shared/api/types';

type ScoredSubmission = ResultsSubmission & { score: number };

// The API publishes a score only for an accepted entry, so an entry with a
// score is an accepted one.
function isAccepted(
  submission: ResultsSubmission,
): submission is ScoredSubmission {
  return submission.score !== null;
}

// The accepted entries, highest score first and by id among equal scores.
export default function acceptedByScore(
  submissions: readonly ResultsSubmission[],
): ResultsSubmission[] {
  return submissions
    .filter(isAccepted)
    .sort((a, b) => b.score - a.score || a.id - b.id);
}
