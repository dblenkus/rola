import {
  AuthorModel,
  ContestModel,
  ImageModel,
  ImageSize,
  SubmissionModel,
  ThemeModel,
} from '../models';

import i18next from 'i18next';

import imageReader from './imageReader';
import { anyImage, countImages } from './image';
import { asyncMap } from '../../../shared/utils/async';

interface BaseError {
  hasError: boolean;
}

interface BaseObject {
  errors: BaseError;
}

// The limits a photograph must meet. The form's rules line shows the same
// figures.
export const fileType = 'image/jpeg';
export const maxFileMegabytes = 5;
export const minLongEdge = 2500;
export const maxLongEdge = 3500;
export const minSeriesImages = 2;

const hasError = (obj: BaseObject | BaseObject[]): boolean => {
  if (Array.isArray(obj)) {
    return obj.some((o) => o.errors.hasError);
  } else {
    return obj.errors.hasError;
  }
};

// What is wrong with a file before it is decoded, or null.
export const fileProblem = (file: File): string | null => {
  if (file.type !== fileType) {
    return i18next.t('jpeg_required');
  }
  if (file.size > maxFileMegabytes * 1024 ** 2) {
    return i18next.t('image_too_large');
  }
  return null;
};

// What is wrong with a decoded photograph's long edge, or null.
export const sizeProblem = ({ width, height }: ImageSize): string | null => {
  if (height < minLongEdge && width < minLongEdge) {
    return i18next.t('long_edge_too_short');
  }
  if (height > maxLongEdge || width > maxLongEdge) {
    return i18next.t('long_edge_too_long');
  }
  return null;
};

const validateImage = async (image: ImageModel): Promise<ImageModel> => {
  const constructResponse = (fileError: string | null): ImageModel => ({
    ...image,
    errors: { file: fileError, hasError: !!fileError },
  });

  const { file } = image;
  if (file) {
    const problem = fileProblem(file);
    if (problem) {
      return constructResponse(problem);
    }

    let img: HTMLImageElement;
    try {
      img = await imageReader(file);
    } catch {
      return constructResponse(i18next.t('invalid_file'));
    }

    return constructResponse(sizeProblem(img));
  }

  return constructResponse(null);
};

// The rules on a submission as a whole, which validation and the entry rows'
// check marks share.

// A series with photographs, but fewer than it needs.
export const tooFewSeriesImages = ({
  meta,
  images,
}: SubmissionModel): boolean =>
  meta.isSeries && anyImage(images) && countImages(images) < minSeriesImages;

export const titleMissing = ({ meta, title }: SubmissionModel): boolean =>
  meta.titleRequired && !title;

export const descriptionMissing = ({
  meta,
  description,
}: SubmissionModel): boolean => meta.descriptionRequired && !description;

const validateSubmission = async (
  submission: SubmissionModel,
): Promise<SubmissionModel> => {
  const { title, description } = submission;
  const images = await asyncMap(submission.images, validateImage);

  if ((title || description) && !anyImage(images) && images[0]) {
    images[0].errors.file = i18next.t('image_required');
    images[0].errors.hasError = true;
  }

  if (tooFewSeriesImages(submission) && images[0]) {
    images[0].errors.file = i18next.t('series_min_images', {
      count: minSeriesImages,
    });
    images[0].errors.hasError = true;
  }

  const noTitle = titleMissing(submission);
  const noDescription = descriptionMissing(submission);
  const errors = {
    description: noDescription ? i18next.t('enter_description') : null,
    title: noTitle ? i18next.t('enter_title') : null,
    hasError: hasError(images) || noDescription || noTitle,
  };

  return { meta: submission.meta, title, description, images, errors };
};

const validateTheme = async (theme: ThemeModel): Promise<ThemeModel> => {
  const submissions = await asyncMap(theme.submissions, validateSubmission);
  const errors = { hasError: hasError(submissions) };

  return { meta: theme.meta, submissions, errors };
};

const validateAuthor = (
  author: AuthorModel,
  initial: boolean,
  contest: ContestModel,
): AuthorModel => {
  const { first_name, last_name, date_of_birth, school, club } = author;
  const errors = {
    first_name: !first_name && !initial ? i18next.t('enter_first_name') : null,
    last_name: !last_name && !initial ? i18next.t('enter_last_name') : null,
    date_of_birth:
      contest.meta.dateOfBirthRequired && !date_of_birth && !initial
        ? i18next.t('enter_dob')
        : null,
    school:
      contest.meta.schoolRequired && !school && !initial
        ? i18next.t('enter_school')
        : null,
    mentor: null,
    club:
      contest.meta.clubRequired && !club && !initial
        ? i18next.t('enter_club')
        : null,
    distinction: null,
    hasError:
      !initial &&
      (!first_name ||
        !last_name ||
        (contest.meta.dateOfBirthRequired && !date_of_birth) ||
        (contest.meta.schoolRequired && !school) ||
        (contest.meta.clubRequired && !club)),
  };

  return { ...author, errors };
};

export default async (
  contest: ContestModel,
  initial = false,
): Promise<ContestModel> => {
  const author = validateAuthor(contest.author, initial, contest);
  const themes = await asyncMap(contest.themes, validateTheme);
  const missingImage =
    !initial &&
    !themes.some((theme) =>
      theme.submissions.some((submission) => anyImage(submission.images)),
    );
  const firstImage = themes[0]?.submissions[0]?.images[0];
  if (missingImage && firstImage) {
    firstImage.errors = {
      file: i18next.t('select_at_least_one_image'),
      hasError: true,
    };
  }
  const errors = {
    hasError: hasError(themes) || hasError(author) || missingImage,
  };

  return { meta: contest.meta, author, themes, errors };
};
