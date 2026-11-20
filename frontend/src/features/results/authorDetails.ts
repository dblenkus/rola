import type { TFunction } from 'i18next';

interface AuthorDetailsParts {
  // The school where the contest shows schools, otherwise the country.
  place: string | null | undefined;
  club?: string | null | undefined;
}

// What the results show in brackets after an author's name: the place and
// the photo club, each only when the author has one. Null when there is
// neither, so that no empty brackets are shown.
export default function authorDetails(
  t: TFunction,
  { place, club }: AuthorDetailsParts,
): string | null {
  if (place && club) {
    return t('author_details_with_club', { details: place, club });
  }
  if (club) return t('author_details_club', { club });
  return place || null;
}
