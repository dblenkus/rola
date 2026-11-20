import React, { useId, useRef, type ReactNode } from 'react';

import { useTranslation } from 'react-i18next';

import Button, { ButtonRow } from '../../../../shared/ui/Button';
import Icon from '../../../../shared/ui/Icon';
import Thumbnail from '../../../../shared/ui/Thumbnail';

import { ImageModel, ImageSize } from '../../models';
import { fileType } from '../../utils/validate';
import './ImageField.css';

export interface ImageFieldProps {
  image: ImageModel;
  handleImageChange: (payload: { file: File | undefined }) => void;
  // The photograph's place in its theme, from 1; names the photograph.
  slot?: number;
  // Shows the check named "OK": the row is complete and has no problem.
  complete?: boolean;
  // The row's text fields, between the photograph and its technical line.
  children?: ReactNode;
}

// The slot as the entrant's rows write it: "01".
export const slotNumber = (slot: number): string =>
  String(slot).padStart(2, '0');

type Orientation = 'landscape' | 'portrait' | 'square';

const orientation = ({ width, height }: ImageSize): Orientation => {
  if (width > height) return 'landscape';
  if (height > width) return 'portrait';
  return 'square';
};

// One photograph slot of an entry row: the photograph whole in the 64 px
// well, the row's fields, the technical line with the slot and the pixel
// size, the file's problem, and the actions. The parts are the row's own
// children, laid out by the rl-entry-row classes.
const ImageField: React.FC<ImageFieldProps> = ({
  image,
  handleImageChange,
  slot,
  complete = false,
  children,
}) => {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const errorId = useId();
  const { file, url, size, errors } = image;
  const problem = errors.file;

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>): void => {
    event.preventDefault();
    const chosen = event.target.files?.[0];
    if (chosen) {
      handleImageChange({ file: chosen });
    }
  };

  const handleRemove = (): void => {
    handleImageChange({ file: undefined });
    // Otherwise the input keeps the file, and choosing the same photograph
    // again fires no change event.
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  };

  const alt =
    slot !== undefined && size !== undefined
      ? t(`upload_photo_alt_${orientation(size)}`, {
          slot: slotNumber(slot),
        })
      : t('selected_photo');

  const technical = (slot !== undefined || size || complete) && (
    <div className="rl-entry-row__tech mono-label">
      {slot !== undefined && (
        <span className="rl-entry-row__slot">{slotNumber(slot)}</span>
      )}
      {size && (
        <span>
          {t('upload_pixel_size', {
            width: size.width,
            height: size.height,
          })}
        </span>
      )}
      {complete && (
        <Icon
          name="check"
          size={14}
          label={t('upload_ok')}
          className="rl-entry-row__ok"
        />
      )}
    </div>
  );

  const describedBy = problem === null ? {} : { 'aria-describedby': errorId };
  const actions = file ? (
    <>
      <Button
        size="dense"
        onPress={() => inputRef.current?.click()}
        {...describedBy}
      >
        {t('change')}
      </Button>
      <Button size="dense" variant="quiet" onPress={handleRemove}>
        {t('remove')}
      </Button>
    </>
  ) : (
    <Button
      size="dense"
      onPress={() => inputRef.current?.click()}
      {...describedBy}
    >
      {t('select')}
    </Button>
  );

  return (
    <>
      <input
        type="file"
        hidden
        aria-label={t('select_photo')}
        accept={fileType}
        onChange={handleChange}
        ref={inputRef}
      />
      {url ? (
        <Thumbnail
          fit="contain"
          size={64}
          src={url}
          alt={alt}
          loading="eager"
        />
      ) : (
        <Thumbnail fit="contain" size={64} label={t('no_photo_selected')} />
      )}
      <div className="rl-entry-row__body">
        {children}
        {problem === null ? (
          <>
            {technical}
            <div className="upload-entry__actions">
              <ButtonRow>{actions}</ButtonRow>
            </div>
          </>
        ) : (
          // A problem with the file, not the field: the field keeps its
          // border, and the message sits beside the action that fixes it.
          <div className="rl-entry-row__problem">
            <div>
              <div className="rl-field__error" id={errorId}>
                <Icon name="alert" />
                <span>{problem}</span>
              </div>
              {technical}
            </div>
            <div className="upload-entry__fix">{actions}</div>
          </div>
        )}
      </div>
    </>
  );
};

export default ImageField;
