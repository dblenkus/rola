import { ImageModel } from '../types/models';

export const anyImage: (images: ImageModel[]) => boolean = (images) => {
    return images.some((image) => !!image.file);
};

export const countImages: (images: ImageModel[]) => number = (images) => {
    return images.filter((image) => !!image.file).length;
}
