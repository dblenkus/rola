import { flatten, without } from 'lodash';
import { DateTime } from 'luxon';

import ImageService from '../services/ImageService';
import { Author } from '../types/api';
import {
    AuthorModel,
    ContestModel,
    ImageModel,
    SubmissionModel,
    ThemeModel,
} from '../types/models';
import SubmissionService from '../services/SubmissionService';
import AuthorService from '../services/AuthorService';

import { asyncMap } from './async';

// interface XXX {
//     files: number[];
//     title: string;
//     description: string;
// }

const processImage = async (image: ImageModel): Promise<any> => {
    const { file } = image;
    if (image.file) {
        const { data } = await ImageService.uploadImage(file!);
        return data;
    }
    return undefined;
};

const processSubmission = async (submission: SubmissionModel): Promise<any> => {
    // let files = await asyncMap(submission.images, processImage);
    let files = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const image of submission.images) {
        // eslint-disable-next-line no-await-in-loop
        const result = await processImage(image);
        files.push(result);
    }

    files = without(files, undefined);
    const { title, description } = submission;

    if (!files.length) return undefined;

    return { files, title, description };
};

const processTheme = async (theme: ThemeModel): Promise<any> => {
    let submissions = await asyncMap(theme.submissions, processSubmission);
    submissions = without(submissions, undefined);
    return flatten(submissions).map((submission) => ({ ...submission, theme: theme.meta.id }));
};

const processAuthor = async (author: AuthorModel): Promise<Author> => {
    const { first_name, last_name, school, mentor, club, distinction } = author;
    const dob = author.dob ? DateTime.fromJSDate(author.dob).toFormat('yyyy-MM-dd') : '';
    const { data } = await AuthorService.create({
        first_name,
        last_name,
        dob,
        school,
        mentor,
        club,
        distinction,
    });
    return data;
};

export default async (contest: ContestModel): Promise<void> => {
    const themes = await asyncMap(contest.themes, processTheme);
    let submissions = flatten(themes);
    const author = await processAuthor(contest.author);
    submissions = submissions.map((submission) => ({ ...submission, author }));
    await SubmissionService.createSubmissions(submissions);
};
