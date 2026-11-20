import {
  AuthorModel,
  ContestModel,
  ImageModel,
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

const minSeriesImages = 2;

const hasError = (obj: BaseObject | BaseObject[]): boolean => {
  if (Array.isArray(obj)) {
    return obj.some((o) => o.errors.hasError);
  } else {
    return obj.errors.hasError;
  }
};

const validateImage = async (image: ImageModel): Promise<ImageModel> => {
  const constructResponse = (fileError: string | null): ImageModel => ({
    ...image,
    errors: { file: fileError, hasError: !!fileError },
  });

  const { file } = image;
  if (file) {
    if (file === undefined) {
      return constructResponse(i18next.t('select_image'));
    }
    if (file.type !== 'image/jpeg') {
      return constructResponse(i18next.t('jpeg_required'));
    }
    if (file.size > 5 * 1024 ** 2) {
      return constructResponse(i18next.t('image_too_large'));
    }

    let img: HTMLImageElement;
    try {
      img = await imageReader(file);
    } catch {
      return constructResponse(i18next.t('invalid_file'));
    }

    if (img.height < 2500 && img.width < 2500)
      return constructResponse(i18next.t('long_edge_too_short'));

    if (img.height > 3500 || img.width > 3500)
      return constructResponse(i18next.t('long_edge_too_long'));
  }

  return constructResponse(null);
};

const validateSubmission = async (
  submission: SubmissionModel,
): Promise<SubmissionModel> => {
  const { title, description } = submission;
  const { titleRequired, descriptionRequired, isSeries } = submission.meta;
  const images = await asyncMap(submission.images, validateImage);

  if ((title || description) && !anyImage(images) && images[0]) {
    images[0].errors.file = i18next.t('image_required');
    images[0].errors.hasError = true;
  }

  if (
    isSeries &&
    anyImage(images) &&
    countImages(images) < minSeriesImages &&
    images[0]
  ) {
    images[0].errors.file = i18next.t('series_min_images', {
      count: minSeriesImages,
    });
    images[0].errors.hasError = true;
  }

  const errors = {
    description:
      descriptionRequired && !description
        ? i18next.t('enter_description')
        : null,
    title: titleRequired && !title ? i18next.t('enter_title') : null,
    hasError:
      hasError(images) ||
      (descriptionRequired && !description) ||
      (titleRequired && !title),
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
  const { first_name, last_name, dob, school, club } = author;
  const errors = {
    first_name: !first_name && !initial ? i18next.t('enter_first_name') : null,
    last_name: !last_name && !initial ? i18next.t('enter_last_name') : null,
    dob:
      contest.meta.dobRequired && !dob && !initial
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
        (contest.meta.dobRequired && !dob) ||
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
