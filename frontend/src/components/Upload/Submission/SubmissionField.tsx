import React from 'react';

import { SubmissionModel, InputChange } from '../../../types/models';

import ImageField from '../Image/ImageField';

import DescriptionField from './DescriptionField';
import ImageGrid from './ImageGrid';
import SeriesGrid from './SeriesGrid';
import TitleField from './TitleField';

export interface SubmissionFieldProps {
    submission: SubmissionModel;
    handleSubmissionChange: (payload: InputChange) => void;
    handleImageChange: (image_id: number, payload: { file: File | undefined }) => void;
}

class SubmissionField extends React.Component<SubmissionFieldProps> {
    render(): React.ReactNode {
        const { submission, handleSubmissionChange, handleImageChange } = this.props;

        const onSubmissionChange = (payload: InputChange): void => handleSubmissionChange(payload);

        const onImageChange = (image_id: number) => (payload: { file: File | undefined }): void =>
            handleImageChange(image_id, payload);

        const titleField = <TitleField submission={submission} onChange={onSubmissionChange} />;
        const descriptionField = (
            <DescriptionField submission={submission} onChange={onSubmissionChange} />
        );

        return (
            <>
                {submission.images.map((image) => {
                    const { id } = image.meta;
                    return (
                        <ImageGrid key={id}>
                            <>
                                <ImageField image={image} handleImageChange={onImageChange(id)} />
                                {submission.meta.isSeries || titleField}
                            </>
                        </ImageGrid>
                    );
                })}
                {submission.meta.isSeries && (
                    <SeriesGrid titleField={titleField} descriptionField={descriptionField} />
                )}
            </>
        );
    }
}

export default SubmissionField;
