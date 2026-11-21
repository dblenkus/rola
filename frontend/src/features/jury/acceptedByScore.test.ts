import { describe, expect, it } from 'vitest';
import { author, submission } from '../../test/fixtures';
import type { ResultsSubmission } from '../../shared/api/types';
import acceptedByScore from './acceptedByScore';

function result(
  id: number,
  accepted: boolean,
  score: number | null,
): ResultsSubmission {
  return {
    ...submission(id, `Entry ${id}`),
    author: { ...author, reward: null, reward_theme: null, country: null },
    files: accepted ? submission(id, '').files : null,
    accepted,
    score,
    reward_kind: null,
    reward_label: null,
  };
}

describe('acceptedByScore', () => {
  it('keeps the accepted entries, highest score first, then by id', () => {
    const results = [
      result(4, true, 20),
      result(2, false, null),
      result(7, true, 35),
      result(3, true, 20),
      result(1, true, 10),
      result(5, false, null),
      result(6, true, 35),
    ];
    expect(acceptedByScore(results).map(({ id }) => id)).toEqual([
      6, 7, 3, 4, 1,
    ]);
  });

  it('leaves the given list as it was', () => {
    const results = [result(1, true, 10), result(2, true, 20)];
    acceptedByScore(results);
    expect(results.map(({ id }) => id)).toEqual([1, 2]);
  });
});
