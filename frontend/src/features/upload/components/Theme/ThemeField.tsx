import React from 'react';

import { useTranslation } from 'react-i18next';

import Strip from '../../../../shared/ui/Strip';
import SubmissionField from '../Submission/SubmissionField';

import { ThemeModel } from '../../models';
import type { InputChange } from '../../../../shared/ui/TextField';
import { countImages } from '../../utils/image';
import {
  maxFileMegabytes,
  maxLongEdge,
  minLongEdge,
  minSeriesImages,
} from '../../utils/validate';

export interface ThemeFieldProps {
  theme: ThemeModel;
  handleSubmissionChange: (submission_id: number, payload: InputChange) => void;
  handleImageChange: (
    submission_id: number,
    image_id: number,
    payload: { file: File | undefined },
  ) => void;
}

// Above this many photographs the segments are too small to count, so the
// strip runs continuously with the same figure.
const maxSegments = 10;

// The segment widths the design system draws: 22 px for up to five steps
// (its default), 16 px for seven, 12 px for ten.
const segmentWidth = (segments: number): { segmentWidth?: number } => {
  if (segments <= 5) return {};
  return { segmentWidth: segments <= 7 ? 16 : 12 };
};

// A theme of the entry: its title, how many of its photographs are selected,
// the rules a photograph must meet, and its entry rows. The theme's photo
// limit is the number of slots the form opened for it (its n_photos).
const ThemeField: React.FC<ThemeFieldProps> = ({
  theme,
  handleSubmissionChange,
  handleImageChange,
}) => {
  const { t } = useTranslation();
  const images = theme.submissions.flatMap(({ images }) => images);
  const total = images.length;
  const selected = countImages(images);
  const isSeries = theme.submissions.some(({ meta }) => meta.isSeries);
  const count = t('upload_photo_count', { selected, count: total });
  const limits = {
    minEdge: minLongEdge,
    maxEdge: maxLongEdge,
    size: maxFileMegabytes,
    count: total,
  };

  // Slots run on through the theme's submissions.
  const firstSlots = theme.submissions.map(
    (_, index) =>
      1 +
      theme.submissions
        .slice(0, index)
        .reduce((sum, { images }) => sum + images.length, 0),
  );
  const submissions = theme.submissions.map((submission, index) => (
    <SubmissionField
      key={submission.meta.id}
      submission={submission}
      firstSlot={firstSlots[index] ?? 1}
      handleSubmissionChange={(payload) =>
        handleSubmissionChange(submission.meta.id, payload)
      }
      handleImageChange={(image_id, payload) =>
        handleImageChange(submission.meta.id, image_id, payload)
      }
    />
  ));

  const continuous = total > maxSegments;
  return (
    <section className="upload-theme">
      <div className="upload-section-head">
        <h2 className="upload-section-head__title h2-mobile">
          {theme.meta.title}
        </h2>
        {total > 0 && (
          <div className="upload-theme__count">
            {/* A continuous strip is a progress bar that names the figure
                itself, so the words beside it are not read twice. */}
            <span className="body-dense" aria-hidden={continuous || undefined}>
              {count}
            </span>
            {continuous ? (
              <Strip value={selected} max={total} label={count} />
            ) : (
              total > 1 && (
                <Strip
                  segments={total}
                  filled={selected}
                  {...segmentWidth(total)}
                  decorative
                />
              )
            )}
          </div>
        )}
        <p className="upload-theme__rules mono-label">
          {isSeries
            ? t('upload_rules_series', {
                ...limits,
                minPhotos: minSeriesImages,
              })
            : t('upload_rules', limits)}
        </p>
      </div>
      {isSeries ? (
        submissions
      ) : (
        <ol className="rl-entry-list">{submissions}</ol>
      )}
    </section>
  );
};

export default ThemeField;
