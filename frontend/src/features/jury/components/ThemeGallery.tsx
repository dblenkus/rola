import React from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

import {
  JurySubmission,
  Rating as RatingModel,
} from '../../../shared/api/types';
import Thumbnail from '../../../shared/ui/Thumbnail';
import ThumbnailGrid from '../../../shared/ui/ThumbnailGrid';
import photoId from './photoId';
import './ThemeGallery.css';

interface ThemeGalleryProps {
  submissions: JurySubmission[];
  ratings: RatingModel[];
  // Where each submission opens in the rater.
  raterLink: (submissionId: number) => string;
  // Called as a submission's link is followed, before the rater opens.
  onOpen: (submissionId: number) => void;
}

// The theme's submissions as thumbnails, each a link to the rater. A cell
// names the photo by its anonymous ID and title and shows the judge's own
// score; a series shows its first photograph and how many it has.
const ThemeGallery: React.FC<ThemeGalleryProps> = ({
  submissions,
  ratings,
  raterLink,
  onOpen,
}: ThemeGalleryProps) => {
  const { t } = useTranslation();

  return (
    <ThumbnailGrid layout="page">
      {submissions.map(({ id, files, title }) => {
        const rating = ratings.find((r) => r.submission === id);
        const [first] = files;
        const caption = (
          <>
            <span className="jury-gallery__id">
              <span>{photoId(id)}</span>
              {files.length > 1 && (
                <span className="jury-gallery__count caption">
                  <span aria-hidden="true">1 / {files.length}</span>
                  <span className="visually-hidden">
                    {t('jury_series_photos', { count: files.length })}
                  </span>
                </span>
              )}
            </span>
            <span className="jury-gallery__score label">
              <span aria-hidden="true">{rating ? rating.rating : '–'}</span>
              <span className="visually-hidden">
                {rating
                  ? t('jury_score', { score: rating.rating })
                  : t('jury_unscored')}
              </span>
            </span>
          </>
        );
        return (
          <Link
            key={id}
            className="jury-gallery__link"
            to={raterLink(id)}
            onClick={() => onOpen(id)}
          >
            {first ? (
              <Thumbnail
                fit="contain"
                src={first.thumbnail || first.file}
                alt={title ?? ''}
                caption={caption}
              />
            ) : (
              <Thumbnail
                fit="contain"
                label={title || photoId(id)}
                caption={caption}
              />
            )}
          </Link>
        );
      })}
    </ThumbnailGrid>
  );
};

export default ThemeGallery;
