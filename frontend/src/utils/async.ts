export const asyncMap = async <T, R>(array: T[], fn: (item: T) => Promise<R>): Promise<R[]> => {
    const promises = array.map((element) => fn(element));
    return await Promise.all(promises);
};
