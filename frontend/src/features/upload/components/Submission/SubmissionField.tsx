import React from 'react';

import { ImageModel, SubmissionModel } from '../../models';
import type { InputChange } from '../../../../shared/ui/TextField';
import { fileProblem, sizeProblem } from '../../utils/validate';

import ImageField, { slotNumber } from '../Image/ImageField';

import DescriptionField from './DescriptionField';
import SeriesGrid from './SeriesGrid';
import TitleField from './TitleField';

export interface SubmissionFieldProps {
  submission: SubmissionModel;
  // The slot of the submission's first photograph in its theme, from 1.
  firstSlot: number;
  handleSubmissionChange: (payload: InputChange) => void;
  handleImageChange: (
    image_id: number,
    payload: { file: File | undefined },
  ) => void;
}

// Whether a photograph is selected, read, and within the limits validation
// checks on upload. The rows show their check mark only then.
const imageAcceptable = ({ file, size, errors }: ImageModel): boolean =>
  file !== undefined &&
  size !== undefined &&
  errors.file === null &&
  fileProblem(file) === null &&
  sizeProblem(size) === null;

// A submission's entry rows. A single photograph's row holds its title; a
// series lists its photographs, then one title and description for the set.
// The theme's list holds the rows of single photographs; a series brings its
// own list.
const SubmissionField: React.FC<SubmissionFieldProps> = ({
  submission,
  firstSlot,
  handleSubmissionChange,
  handleImageChange,
}) => {
  const { isSeries } = submission.meta;
  const titled = !!submission.title && submission.errors.title === null;

  const rows = submission.images.map((image, index) => {
    const slot = firstSlot + index;
    const { id } = image.meta;
    return (
      <li key={id} className="rl-entry-row">
        <ImageField
          image={image}
          slot={slot}
          complete={imageAcceptable(image) && (isSeries || titled)}
          handleImageChange={(payload) => handleImageChange(id, payload)}
        >
          {isSeries || (
            <TitleField
              submission={submission}
              slot={slotNumber(slot)}
              onChange={handleSubmissionChange}
            />
          )}
        </ImageField>
      </li>
    );
  });

  if (!isSeries) {
    return <>{rows}</>;
  }
  return (
    <>
      <ol className="rl-entry-list">{rows}</ol>
      <SeriesGrid
        titleField={
          <TitleField
            submission={submission}
            onChange={handleSubmissionChange}
          />
        }
        descriptionField={
          <DescriptionField
            submission={submission}
            onChange={handleSubmissionChange}
          />
        }
      />
    </>
  );
};

export default SubmissionField;
