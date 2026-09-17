import React from 'react';

import ThemeCard from './ThemeCard';
import SubmissionField from '../Submission/SubmissionField';

import { InputChange, ThemeModel } from '../../../types/models';

export interface ThemeFieldProps {
    theme: ThemeModel;
    handleSubmissionChange: (submission_id: number, payload: InputChange) => void;
    handleImageChange: (
        submission_id: number,
        image_id: number,
        payload: { file: File | undefined },
    ) => void;
}

class ThemeField extends React.Component<ThemeFieldProps> {
    render(): React.ReactNode {
        const { handleSubmissionChange, handleImageChange, theme } = this.props;

        const onSubmissionChange = (submission_id: number) => (payload: InputChange): void =>
            handleSubmissionChange(submission_id, payload);

        const onImageChange = (submission_id: number) => (
            image_id: number,
            payload: { file: File | undefined },
        ): void => handleImageChange(submission_id, image_id, payload);

        return (
            <ThemeCard title={theme.meta.title}>
                {theme.submissions.map((submission) => {
                    const { id } = submission.meta;
                    return (
                        <SubmissionField
                            key={id}
                            submission={submission}
                            handleSubmissionChange={onSubmissionChange(id)}
                            handleImageChange={onImageChange(id)}
                        />
                    );
                })}
            </ThemeCard>
        );
    }
}

export default ThemeField;
