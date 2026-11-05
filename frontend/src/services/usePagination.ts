import axios, { AxiosPromise } from 'axios';
import { useEffect, useState } from 'react';

import { BaseResource, PaginatedResponse } from '../types/api';
import { requestError } from './errors';

interface PaginationProps<R> {
  // Must keep its identity between renders; a new function reloads the page.
  source: (
    page: number,
    pageSize: number,
  ) => AxiosPromise<PaginatedResponse<R>>;
  // Change it to reload the current page.
  reloadKey: number;
}

interface PaginationReturn<R> {
  error: string | null;
  isLoading: boolean;
  data: R[];
  count: number;
  page: number;
  pageSize: number;
  changePage: (pageNumber: number) => void;
  changePageSize: (newPageSize: number) => void;
}

function usePagination<R extends BaseResource>({
  source,
  reloadKey,
}: PaginationProps<R>): PaginationReturn<R> {
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setLoading] = useState(true);
  const [data, setData] = useState<R[]>([]);
  const [count, setCount] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // A change of inputs starts a new request in the effect below. Resetting
  // its state here, during render, keeps the previous result off screen.
  const [requested, setRequested] = useState({
    source,
    reloadKey,
    page,
    pageSize,
  });
  if (
    requested.source !== source ||
    requested.reloadKey !== reloadKey ||
    requested.page !== page ||
    requested.pageSize !== pageSize
  ) {
    setRequested({ source, reloadKey, page, pageSize });
    setError(null);
    setLoading(true);
  }

  useEffect(() => {
    let active = true;
    source(page, pageSize)
      .then(({ data: responseData }) => {
        if (!active) return;
        setData(responseData.results);
        setCount(responseData.count);
        setLoading(false);
      })
      .catch((error: unknown) => {
        if (!active) return;
        // The API answers a page past the end with 404, for example after the
        // last row of the last page was deleted; show the page before it.
        if (
          page > 1 &&
          axios.isAxiosError(error) &&
          error.response?.status === 404
        ) {
          setPage(page - 1);
          return;
        }
        setError(requestError(error));
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [source, page, pageSize, reloadKey]);

  const changePage = (pageNumber: number): void => setPage(pageNumber);

  const changePageSize = (newPageSize: number): void => {
    setPageSize(newPageSize);
    setPage(1);
  };

  return {
    error,
    isLoading,
    data,
    count,
    page,
    pageSize,
    changePage,
    changePageSize,
  };
}

export default usePagination;
