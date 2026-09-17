export interface PaginatedResponse<R> {
    count: number;
    results: R[];
    next: string | null;
    previous: string | null;
}

export interface BaseResource {
    id: number;
    created: string;
    modified: string;
}

export interface Image extends BaseResource {
    file: string;
    thumbnail: string;
}

export interface Institution extends BaseResource {
    name: string;
    kind: number;
}

export interface Author extends BaseResource {
    first_name: string;
    last_name: string;
    email: string;
}

export interface ResultsAuthor extends Author {
    reward: string | null;
    reward_theme: number | null;
    country: string | null;
    school: string | null;
    club: string | null;
}

export interface Submission extends BaseResource {
    theme: number;
    author: Author;
    title: string;
    description: string;
    files: Image[];
}

export interface ResultsSubmission extends Submission {
    author: ResultsAuthor;
    rating: number;
    reward_kind: 'Gold' | 'Silver' | 'Bronze' | 'Honorable Mention';
    reward_label: string;
    accepted: boolean;
}

export interface SubmissionSet extends BaseResource {
    contest: number;
    author: Author;
    submissions: Submission[];
}

export interface Theme extends BaseResource {
    title: string;
    is_series: boolean;
    n_photos: number;
    submissions_number: number;
}

export interface JuryTheme extends Theme {
    ratings_number: number;
}

export interface ResultsTheme extends Theme {
    submissions: ResultsSubmission[];
}

export interface Contest extends BaseResource {
    title: string;
    description: string;
    themes: Theme[];
    start_date: string;
    end_date: string;
    notice_html: string;
    confirmation_html: string;
    header_image: string | null;
    dob_required: boolean;
    club_show: boolean;
    club_required: boolean;
    school_show: boolean;
    school_required: boolean;
}

export interface JuryContest extends Contest {
    themes: JuryTheme[];
}

export interface Payment extends BaseResource {
    submissionset: number;
    paid: boolean;
}

export interface Rating extends BaseResource {
    submission: number;
    rating: number;
}
