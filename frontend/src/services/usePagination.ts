import { AxiosPromise } from 'axios';
import { useEffect, useState } from 'react';

import { BaseResource, PaginatedResponse } from '../types/api';

interface PaginationProps<R> {
    source: (page: number, pageSize: number) => AxiosPromise<PaginatedResponse<R>>;
}

interface PaginationReturn<R> {
    data: R[];
    count: number;
    page: number;
    pageSize: number;
    changePage: (pageNumber: number) => void;
    changePageSize: (newPageSize: number) => void;
}

function usePagination<R extends BaseResource>({
    source,
}: PaginationProps<R>): PaginationReturn<R> {
    const [data, setData] = useState<R[]>([]);
    const [count, setCount] = useState(0);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);

    useEffect(() => {
        const fetchData = async (): Promise<void> => {
            const { data: respondeData } = await source(page, pageSize);
            setData(respondeData.results);
            setCount(respondeData.count);
        };
        fetchData();
    }, [source, page, pageSize]);

    const changePage = (pageNumber: number): void => setPage(pageNumber);

    const changePageSize = (newPageSize: number): void => {
        setPageSize(newPageSize);
        setPage(1);
    };

    return { data, count, page, pageSize, changePage, changePageSize };
}

export default usePagination;
