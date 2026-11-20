import { AxiosError, AxiosHeaders } from 'axios';
import i18next from 'i18next';
import { describe, expect, it, onTestFinished, vi } from 'vitest';
import { httpError } from '../../test/api';
import { requestError } from './errors';

describe('request errors', () => {
  it('reports an error that is not a failed request', () => {
    const queued = vi
      .spyOn(globalThis, 'queueMicrotask')
      .mockImplementation(() => {});
    const bug = new TypeError('bug');
    expect(requestError(bug)).toBe('Request failed. Please try again.');
    expect(queued).toHaveBeenCalledOnce();
    expect(() => queued.mock.calls[0]?.[0]()).toThrow(bug);
    queued.mockRestore();
  });

  it('reports nothing for a failed request', () => {
    const queued = vi
      .spyOn(globalThis, 'queueMicrotask')
      .mockImplementation(() => {});
    const failure = new AxiosError('Network Error', AxiosError.ERR_NETWORK);
    expect(requestError(failure)).toBe('Request failed. Please try again.');
    expect(queued).not.toHaveBeenCalled();
    queued.mockRestore();
  });

  it('tells that the server did not respond in time', () => {
    const timeout = new AxiosError(
      'timeout of 30000ms exceeded',
      AxiosError.ETIMEDOUT,
    );
    expect(requestError(timeout)).toBe(
      'The server did not respond in time. Please try again.',
    );
  });

  it('tells how long to wait after too many requests', () => {
    const config = { headers: new AxiosHeaders() };
    const throttled = (headers: Record<string, string>) =>
      requestError(httpError(config, 429, {}, headers));
    expect(throttled({ 'retry-after': '3600' })).toBe(
      'Too many requests from this network. Please try again in 60 minutes.',
    );
    expect(throttled({ 'retry-after': '61' })).toBe(
      'Too many requests from this network. Please try again in 2 minutes.',
    );
    expect(throttled({ 'retry-after': '1' })).toBe(
      'Too many requests from this network. Please try again in 1 minute.',
    );
    expect(throttled({ 'retry-after': 'Fri, 06 Nov 2026 19:00:00 GMT' })).toBe(
      'Too many requests from this network. Please try again later.',
    );
    expect(throttled({})).toBe(
      'Too many requests from this network. Please try again later.',
    );
  });

  it('counts the minutes to wait in the interface language', async () => {
    await i18next.changeLanguage('sl');
    onTestFinished(async () => {
      await i18next.changeLanguage('en');
    });
    const config = { headers: new AxiosHeaders() };
    const wait = (seconds: number) =>
      requestError(
        httpError(config, 429, {}, { 'retry-after': String(seconds * 60) }),
      );
    const tooMany = 'Preveč zahtev iz tega omrežja. Poskusi znova čez';
    expect(wait(1)).toBe(`${tooMany} 1 minuto.`);
    expect(wait(2)).toBe(`${tooMany} 2 minuti.`);
    expect(wait(3)).toBe(`${tooMany} 3 minute.`);
    expect(wait(5)).toBe(`${tooMany} 5 minut.`);
  });
});
