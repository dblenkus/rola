export const readFile = (inputFile: File): Promise<string> =>
    new Promise((resolve, reject) => {
        const fileReader = new FileReader();
        fileReader.onerror = () => {
            fileReader.abort();
            reject(new DOMException('Problem reading input file.'));
        };
        fileReader.onload = () => {
            resolve(fileReader.result as string);
        };
        fileReader.readAsDataURL(inputFile);
    });

const imageReader = async (inputFile: File): Promise<HTMLImageElement> => {
    const fileContent = await readFile(inputFile);

    return new Promise((resolve, reject) => {
        const image = new Image();
        image.onerror = () => {
            reject(new DOMException('Problem reading input file.'));
        };
        image.onload = () => {
            resolve(image);
        };
        image.src = fileContent;
    });
};

export default imageReader;
