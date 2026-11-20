import { afterEach, describe, expect, it, vi } from 'vitest';

import { handleWorkerMessage, precachedPaths } from './workerMessageHandler';

const WORKER_URL = 'https://rola.test/sw.js';
const ASKER = 'client-asker';
const ENTRY_SCRIPT_URL = 'https://rola.test/assets/index-abc123.js';

describe('precachedPaths', () => {
  it('resolves the entries with and without a revision to path names', () => {
    const paths = precachedPaths(
      [
        { url: 'index.html', revision: 'a1b2' },
        { url: 'assets/index-abc123.js', revision: null },
        'assets/ThemeResults-def456.js',
        { url: '/icon-192.png' },
      ],
      WORKER_URL,
    );

    expect([...paths]).toEqual([
      '/index.html',
      '/assets/index-abc123.js',
      '/assets/ThemeResults-def456.js',
      '/icon-192.png',
    ]);
  });
});

/** A worker that precaches `precached` while the `windows` are open. */
function worker(
  precached: readonly string[] = [],
  windows: readonly string[] = [ASKER],
) {
  const paths = precachedPaths(precached, WORKER_URL);
  return {
    skipWaiting: vi.fn(),
    isPrecached: (path: string) => paths.has(path),
    windowClientIds: vi.fn(() => Promise.resolve(windows)),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

function port() {
  return { postMessage: vi.fn() };
}

describe('handleWorkerMessage', () => {
  it('takes over on SKIP_WAITING', async () => {
    const actions = worker();

    await handleWorkerMessage(
      { type: 'SKIP_WAITING' },
      undefined,
      ASKER,
      actions,
    );

    expect(actions.skipWaiting).toHaveBeenCalledOnce();
  });

  it('answers that a page whose entry script it precaches is its build', async () => {
    const actions = worker(['index.html', 'assets/index-abc123.js']);
    const reply = port();

    await handleWorkerMessage(
      { type: 'IS_SAME_BUILD', entryScriptUrl: ENTRY_SCRIPT_URL },
      reply,
      ASKER,
      actions,
    );

    expect(reply.postMessage).toHaveBeenCalledExactlyOnceWith({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: false,
    });
    expect(actions.skipWaiting).not.toHaveBeenCalled();
  });

  it.each([
    ['another build', 'https://rola.test/assets/index-old999.js'],
    ['an unparsable URL', 'not a url'],
    ['a URL that the URL parser rejects', 'https://rola.test:99999/x.js'],
    ['a relative URL', '/assets/index-abc123.js'],
  ])('answers that a page with %s is not its build', async (_name, url) => {
    const reply = port();

    await handleWorkerMessage(
      { type: 'IS_SAME_BUILD', entryScriptUrl: url },
      reply,
      ASKER,
      worker(['assets/index-abc123.js']),
    );

    expect(reply.postMessage).toHaveBeenCalledExactlyOnceWith({
      type: 'SAME_BUILD',
      sameBuild: false,
      otherWindows: false,
    });
  });

  it('does not rely on URL.canParse, which older Safari lacks', async () => {
    vi.spyOn(URL, 'canParse').mockImplementation(() => {
      throw new TypeError('URL.canParse is not a function');
    });
    const reply = port();

    await handleWorkerMessage(
      { type: 'IS_SAME_BUILD', entryScriptUrl: ENTRY_SCRIPT_URL },
      reply,
      ASKER,
      worker(['assets/index-abc123.js']),
    );

    expect(reply.postMessage).toHaveBeenCalledExactlyOnceWith({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: false,
    });
  });

  it.each([
    ['another window is open', [ASKER, 'client-other'], ASKER],
    ['only another window is listed', ['client-other'], ASKER],
    ['the asker is not a client', [ASKER], null],
  ])(
    'answers that other windows may exist when %s',
    async (_name, windows, askerId) => {
      const reply = port();

      await handleWorkerMessage(
        { type: 'IS_SAME_BUILD', entryScriptUrl: ENTRY_SCRIPT_URL },
        reply,
        askerId,
        worker(['assets/index-abc123.js'], windows),
      );

      expect(reply.postMessage).toHaveBeenCalledExactlyOnceWith({
        type: 'SAME_BUILD',
        sameBuild: true,
        otherWindows: true,
      });
    },
  );

  it('answers that other windows may exist when it cannot list them', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const actions = worker(['assets/index-abc123.js']);
    actions.windowClientIds.mockRejectedValue(new Error('No clients'));
    const reply = port();

    await handleWorkerMessage(
      { type: 'IS_SAME_BUILD', entryScriptUrl: ENTRY_SCRIPT_URL },
      reply,
      ASKER,
      actions,
    );

    expect(reply.postMessage).toHaveBeenCalledExactlyOnceWith({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: true,
    });
    expect(warn).toHaveBeenCalledOnce();
  });

  it('ignores IS_SAME_BUILD without a port', async () => {
    const actions = worker(['assets/index-abc123.js']);

    await expect(
      handleWorkerMessage(
        { type: 'IS_SAME_BUILD', entryScriptUrl: ENTRY_SCRIPT_URL },
        undefined,
        ASKER,
        actions,
      ),
    ).resolves.toBeUndefined();
    expect(actions.skipWaiting).not.toHaveBeenCalled();
  });

  it.each([
    ['a message of another type', { type: 'OTHER' }],
    ['a message without a type', { entryScriptUrl: 'x' }],
    ['IS_SAME_BUILD without a URL', { type: 'IS_SAME_BUILD' }],
    [
      'IS_SAME_BUILD with a number',
      { type: 'IS_SAME_BUILD', entryScriptUrl: 1 },
    ],
    ['a string', 'SKIP_WAITING'],
    ['null', null],
  ])('ignores %s', async (_name, data) => {
    const actions = worker(['assets/index-abc123.js']);
    const reply = port();

    await handleWorkerMessage(data, reply, ASKER, actions);

    expect(actions.skipWaiting).not.toHaveBeenCalled();
    expect(reply.postMessage).not.toHaveBeenCalled();
  });
});
