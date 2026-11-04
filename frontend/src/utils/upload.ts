import { flatten } from 'lodash';
import { DateTime } from 'luxon';

import ImageService from '../services/ImageService';
import { Author, Image } from '../types/api';
import {
  AuthorModel,
  ContestModel,
  ImageModel,
  SubmissionModel,
  ThemeModel,
} from '../types/models';
import SubmissionService, {
  type SubmissionCreatePayload,
} from '../services/SubmissionService';
import AuthorService from '../services/AuthorService';

import { asyncMap } from './async';

// interface XXX {
//     files: number[];
//     title: string;
//     description: string;
// }

type ThemeSubmission = Omit<SubmissionCreatePayload, 'author'>;

const processImage = async (image: ImageModel): Promise<Image | undefined> => {
  const { file } = image;
  if (file) {
    const { data } = await ImageService.uploadImage(file);
    return data;
  }
  return undefined;
};

const processSubmission = async (
  submission: SubmissionModel,
): Promise<Omit<ThemeSubmission, 'theme'> | undefined> => {
  // let files = await asyncMap(submission.images, processImage);
  const files: Image[] = [];
  for (const image of submission.images) {
    const result = await processImage(image);
    if (result) {
      files.push(result);
    }
  }

  const { title, description } = submission;

  if (!files.length) return undefined;

  return { files, title, description };
};

const processTheme = async (theme: ThemeModel): Promise<ThemeSubmission[]> => {
  const submissions = await asyncMap(theme.submissions, processSubmission);
  return submissions
    .filter((submission) => submission !== undefined)
    .map((submission) => ({
      ...submission,
      theme: theme.meta.id,
    }));
};

const processAuthor = async (author: AuthorModel): Promise<Author> => {
  const { first_name, last_name, school, mentor, club, distinction } = author;
  const dob = author.dob
    ? DateTime.fromJSDate(author.dob).toFormat('yyyy-MM-dd')
    : '';
  const { data } = await AuthorService.create({
    first_name,
    last_name,
    dob,
    school: school ?? '',
    mentor: mentor ?? '',
    club: club ?? '',
    distinction,
  });
  return data;
};

export default async (contest: ContestModel): Promise<void> => {
  const themes = await asyncMap(contest.themes, processTheme);
  const submissions = flatten(themes);
  const author = await processAuthor(contest.author);
  await SubmissionService.createSubmissions(
    submissions.map((submission) => ({ ...submission, author })),
  );
};
