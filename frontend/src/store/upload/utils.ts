import {
    AuthorError,
    AuthorModel,
    ContestError,
    ContestModel,
    ImageError,
    ImageModel,
    ThemeError,
    ThemeModel,
    SubmissionError,
    SubmissionModel,
} from '../../types/models';

export const getEmptyContestError = (): ContestError => ({
    hasError: false,
});

export const getEmptyAuthorError = (): AuthorError => ({
    hasError: false,
    first_name: null,
    last_name: null,
    dob: null,
    school: null,
    mentor: null,
    club: null,
    distinction: null,
});

export const getEmptyThemeError = (): ThemeError => ({
    hasError: false,
});

export const getEmptySubmissionError = (): SubmissionError => ({
    hasError: false,
    title: null,
    description: null,
});

export const getEmptyImageError = (): ImageError => ({
    hasError: false,
    file: null,
});

export const getEmptyContest = (): ContestModel => ({
    meta: {
        title: '',
        description: '',
        noticeHtml: '',
        headerImage: null,
        dobRequired: false,
        clubShow: false,
        clubRequired: false,
        schoolShow: false,
        schoolRequired: false,
    },
    author: getEmptyAuthor(),
    themes: [],
    errors: getEmptyContestError(),
});

export const getEmptyAuthor = (): AuthorModel => ({
    first_name: '',
    last_name: '',
    dob: undefined,
    school: '',
    mentor: '',
    club: '',
    distinction: '',
    errors: getEmptyAuthorError(),
});

export const getEmptyTheme = (): ThemeModel => ({
    meta: {
        id: 0,
        title: '',
    },
    submissions: [],
    errors: getEmptySubmissionError(),
});

export const getEmptySubmission = (): SubmissionModel => ({
    meta: {
        id: 0,
        imageNumber: 0,
        isChanged: false,
        isNew: true,
        isSeries: false,
        titleRequired: false,
        descriptionRequired: false,
    },
    title: '',
    description: '',
    images: [],
    errors: getEmptySubmissionError(),
});

export const getEmptyImage = (): ImageModel => ({
    meta: {
        id: 0,
        isChanged: false,
        isNew: true,
    },
    file: undefined,
    url: '',
    errors: getEmptyImageError(),
});
