import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Reloading is the browser navigation the module ends in; jsdom has none.
vi.mock('./reloadPage', () => ({ reloadPage: vi.fn() }));

const MINUTE_MS = 60 * 1000;
const ENTRY_SCRIPT = '/assets/index-abc123.js';

/** A MessageChannel whose port2 delivers to port1 at once. */
class FakeMessageChannel {
  port1 = {
    onmessage: null as ((event: { data: unknown }) => void) | null,
    close: vi.fn(),
  };
  port2 = {
    postMessage: (data: unknown) => {
      this.port1.onmessage?.({ data });
    },
  };
}

type FakePort = FakeMessageChannel['port2'];

function isFakePort(value: unknown): value is FakePort {
  return (
    typeof value === 'object' &&
    value !== null &&
    'postMessage' in value &&
    typeof value.postMessage === 'function'
  );
}

class FakeWorker extends EventTarget {
  state: ServiceWorkerState;
  postMessage = vi.fn();

  constructor(state: ServiceWorkerState) {
    super();
    this.state = state;
  }

  /** Answers IS_SAME_BUILD with `reply` on the port sent with it. */
  answers(reply: unknown): this {
    this.postMessage.mockImplementation(
      (message: unknown, transfer: unknown) => {
        const port: unknown = Array.isArray(transfer) ? transfer[0] : null;
        if (
          typeof message === 'object' &&
          message !== null &&
          'type' in message &&
          message.type === 'IS_SAME_BUILD' &&
          isFakePort(port)
        ) {
          port.postMessage(reply);
        }
      },
    );
    return this;
  }

  becomes(state: ServiceWorkerState) {
    this.state = state;
    this.dispatchEvent(new Event('statechange'));
  }
}

class FakeRegistration extends EventTarget {
  installing: FakeWorker | null = null;
  waiting: FakeWorker | null;
  update = vi.fn(() => Promise.resolve());

  constructor(waiting: FakeWorker | null = null) {
    super();
    this.waiting = waiting;
  }

  /** What the browser does when it finds a new sw.js. */
  startInstalling(): FakeWorker {
    const worker = new FakeWorker('installing');
    this.installing = worker;
    this.dispatchEvent(new Event('updatefound'));
    return worker;
  }
}

class FakeContainer extends EventTarget {
  controller: object | null;
  register: ReturnType<typeof vi.fn>;

  constructor(
    controller: object | null,
    register: () => Promise<FakeRegistration>,
  ) {
    super();
    this.controller = controller;
    this.register = vi.fn(register);
  }

  /** What the browser does when a new worker takes over the tab. */
  takeOver() {
    this.controller = {};
    this.dispatchEvent(new Event('controllerchange'));
  }
}

/** Fresh copies of the module and its reload mock: the update is module state. */
async function loadModule() {
  vi.resetModules();
  const module = await import('./registerServiceWorker');
  const { reloadPage } = await import('./reloadPage');
  return { ...module, reloadPage };
}

/**
 * Keeps 'load' listeners off the shared jsdom window, so no test's listener
 * runs in another, and returns them so a test can fire the load.
 */
function captureLoadListeners(): (() => void)[] {
  const listeners: (() => void)[] = [];
  const add = window.addEventListener.bind(window);
  vi.spyOn(window, 'addEventListener').mockImplementation(
    (type, listener, options) => {
      if (type === 'load' && typeof listener === 'function') {
        listeners.push(() => {
          listener(new Event('load'));
        });
        return;
      }
      add(type, listener, options);
    },
  );
  return listeners;
}

function installContainer(container: FakeContainer) {
  Object.defineProperty(navigator, 'serviceWorker', {
    configurable: true,
    value: container,
  });
}

/** Registers with `registration` in a tab with or without a controller. */
async function registered(
  registration: FakeRegistration,
  controller: object | null = {},
) {
  const module = await loadModule();
  const loads = captureLoadListeners();
  const container = new FakeContainer(controller, () =>
    Promise.resolve(registration),
  );
  installContainer(container);
  module.registerServiceWorker();
  for (const fire of loads) fire();
  await vi.runAllTimersAsync();
  return { ...module, container };
}

function show() {
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  document.dispatchEvent(new Event('visibilitychange'));
}

function hide() {
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
  document.dispatchEvent(new Event('visibilitychange'));
}

/** Gives the page the entry script that the build puts into index.html. */
function addEntryScript() {
  const script = document.createElement('script');
  script.type = 'module';
  script.src = ENTRY_SCRIPT;
  document.head.append(script);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-11-20T10:00:00Z'));
  vi.stubGlobal('MessageChannel', FakeMessageChannel);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, 'serviceWorker');
  document.head.replaceChildren();
});

describe('registerServiceWorker', () => {
  it('does nothing without service worker support', async () => {
    const { registerServiceWorker, isUpdateReady } = await loadModule();
    const loads = captureLoadListeners();

    registerServiceWorker();

    expect(loads).toEqual([]);
    expect(isUpdateReady()).toBe(false);
  });

  it('registers /sw.js for the whole site once the page has loaded', async () => {
    const { registerServiceWorker } = await loadModule();
    const loads = captureLoadListeners();
    const container = new FakeContainer(null, () =>
      Promise.resolve(new FakeRegistration()),
    );
    installContainer(container);

    registerServiceWorker();
    expect(container.register).not.toHaveBeenCalled();
    for (const fire of loads) fire();

    expect(container.register).toHaveBeenCalledExactlyOnceWith('/sw.js', {
      scope: '/',
    });
  });

  it('logs a failed registration', async () => {
    const { registerServiceWorker, isUpdateReady } = await loadModule();
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const loads = captureLoadListeners();
    installContainer(
      new FakeContainer(null, () => Promise.reject(new Error('Bad script'))),
    );

    registerServiceWorker();
    for (const fire of loads) fire();
    await vi.runAllTimersAsync();

    expect(error).toHaveBeenCalledOnce();
    expect(isUpdateReady()).toBe(false);
  });
});

describe('an update', () => {
  it('is ready when a worker already waits at registration', async () => {
    const { isUpdateReady } = await registered(
      new FakeRegistration(new FakeWorker('installed')),
    );

    expect(isUpdateReady()).toBe(true);
  });

  it('is not ready for a waiting worker in a tab loaded without one', async () => {
    const { isUpdateReady } = await registered(
      new FakeRegistration(new FakeWorker('installed')),
      null,
    );

    expect(isUpdateReady()).toBe(false);
  });

  it('is ready when a new worker installs in a controlled tab', async () => {
    const registration = new FakeRegistration();
    const { isUpdateReady, subscribeToUpdate } = await registered(registration);
    const listener = vi.fn();
    subscribeToUpdate(listener);

    const worker = registration.startInstalling();
    expect(isUpdateReady()).toBe(false);
    worker.becomes('installed');
    await vi.runAllTimersAsync();

    expect(isUpdateReady()).toBe(true);
    expect(listener).toHaveBeenCalledOnce();
  });

  it('is not ready on the first install', async () => {
    const registration = new FakeRegistration();
    const { isUpdateReady } = await registered(registration, null);

    registration.startInstalling().becomes('installed');

    expect(isUpdateReady()).toBe(false);
  });

  it('is put off by dismissUpdate until the next worker waits', async () => {
    const registration = new FakeRegistration();
    const { isUpdateReady, dismissUpdate } = await registered(registration);
    registration.startInstalling().becomes('installed');
    await vi.runAllTimersAsync();

    dismissUpdate();
    expect(isUpdateReady()).toBe(false);
    registration.startInstalling().becomes('installed');
    await vi.runAllTimersAsync();

    expect(isUpdateReady()).toBe(true);
  });
});

describe('a waiting worker built with this page', () => {
  it('takes over without a prompt and without a reload', async () => {
    addEntryScript();
    const registration = new FakeRegistration();
    const { container, isUpdateReady, reloadPage, subscribeToUpdate } =
      await registered(registration);
    const listener = vi.fn();
    subscribeToUpdate(listener);
    const worker = registration.startInstalling();
    worker.answers({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: false,
    });

    worker.becomes('installed');
    await vi.runAllTimersAsync();

    expect(worker.postMessage).toHaveBeenCalledWith(
      {
        type: 'IS_SAME_BUILD',
        entryScriptUrl: new URL(ENTRY_SCRIPT, document.baseURI).href,
      },
      [expect.anything()],
    );
    expect(worker.postMessage).toHaveBeenLastCalledWith({
      type: 'SKIP_WAITING',
    });
    container.takeOver();
    expect(isUpdateReady()).toBe(false);
    expect(listener).not.toHaveBeenCalled();
    expect(reloadPage).not.toHaveBeenCalled();
  });

  it('takes over when it already waits at registration', async () => {
    addEntryScript();
    const worker = new FakeWorker('installed').answers({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: false,
    });

    const { isUpdateReady } = await registered(new FakeRegistration(worker));

    expect(worker.postMessage).toHaveBeenLastCalledWith({
      type: 'SKIP_WAITING',
    });
    expect(isUpdateReady()).toBe(false);
  });
});

describe('a waiting worker built with this page while other windows may be open', () => {
  /** A worker that installs and answers that other windows are open. */
  async function waitingWhileOthersOpen(reply: unknown) {
    addEntryScript();
    const registration = new FakeRegistration();
    const module = await registered(registration);
    const listener = vi.fn();
    module.subscribeToUpdate(listener);
    const worker = registration.startInstalling().answers(reply);
    worker.becomes('installed');
    await vi.runAllTimersAsync();
    registration.installing = null;
    registration.waiting = worker;
    return { ...module, listener, registration, worker };
  }

  it.each([
    [
      'it answers that they are',
      { type: 'SAME_BUILD', sameBuild: true, otherWindows: true },
    ],
    ['it does not say', { type: 'SAME_BUILD', sameBuild: true }],
    [
      'the answer is not a boolean',
      { type: 'SAME_BUILD', sameBuild: true, otherWindows: 'false' },
    ],
  ])('neither takes over nor is offered when %s', async (_name, reply) => {
    const { isUpdateReady, listener, worker } =
      await waitingWhileOthersOpen(reply);

    expect(worker.postMessage).toHaveBeenCalledOnce();
    expect(worker.postMessage).not.toHaveBeenCalledWith({
      type: 'SKIP_WAITING',
    });
    expect(isUpdateReady()).toBe(false);
    expect(listener).not.toHaveBeenCalled();
  });

  it('is asked again at the next update check and takes over once alone', async () => {
    const { isUpdateReady, registration, worker } =
      await waitingWhileOthersOpen({
        type: 'SAME_BUILD',
        sameBuild: true,
        otherWindows: true,
      });
    worker.answers({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: false,
    });

    vi.advanceTimersByTime(MINUTE_MS + 1);
    show();
    await vi.runAllTimersAsync();

    expect(registration.update).toHaveBeenCalledOnce();
    expect(worker.postMessage).toHaveBeenCalledTimes(3);
    expect(worker.postMessage).toHaveBeenLastCalledWith({
      type: 'SKIP_WAITING',
    });
    expect(isUpdateReady()).toBe(false);
  });

  it('keeps waiting at the next update check while others are still open', async () => {
    const { isUpdateReady, worker } = await waitingWhileOthersOpen({
      type: 'SAME_BUILD',
      sameBuild: true,
      otherWindows: true,
    });

    vi.advanceTimersByTime(MINUTE_MS + 1);
    window.dispatchEvent(new Event('focus'));
    await vi.runAllTimersAsync();

    expect(worker.postMessage).toHaveBeenCalledTimes(2);
    expect(worker.postMessage).not.toHaveBeenCalledWith({
      type: 'SKIP_WAITING',
    });
    expect(isUpdateReady()).toBe(false);
  });
});

describe('a waiting worker not known to be built with this page', () => {
  /** A worker that installs and answers `reply`, or nothing if undefined. */
  async function waitingWorkerAnswering(reply: unknown) {
    addEntryScript();
    const registration = new FakeRegistration();
    const module = await registered(registration);
    const worker = registration.startInstalling();
    if (reply !== undefined) worker.answers(reply);
    worker.becomes('installed');
    return { ...module, worker };
  }

  it('is offered when it answers that the page is an older build', async () => {
    const { isUpdateReady, worker } = await waitingWorkerAnswering({
      type: 'SAME_BUILD',
      sameBuild: false,
    });
    await vi.advanceTimersByTimeAsync(0);

    expect(isUpdateReady()).toBe(true);
    expect(worker.postMessage).not.toHaveBeenCalledWith({
      type: 'SKIP_WAITING',
    });
  });

  it('is offered to an older build while other windows are open', async () => {
    const { isUpdateReady, worker } = await waitingWorkerAnswering({
      type: 'SAME_BUILD',
      sameBuild: false,
      otherWindows: true,
    });
    await vi.advanceTimersByTimeAsync(0);

    expect(isUpdateReady()).toBe(true);
    expect(worker.postMessage).toHaveBeenCalledOnce();
  });

  it('is offered when it does not answer in time', async () => {
    const { isUpdateReady, worker, SAME_BUILD_TIMEOUT_MS } =
      await waitingWorkerAnswering(undefined);

    await vi.advanceTimersByTimeAsync(SAME_BUILD_TIMEOUT_MS - 1);
    expect(isUpdateReady()).toBe(false);
    await vi.advanceTimersByTimeAsync(1);

    expect(isUpdateReady()).toBe(true);
    expect(worker.postMessage).toHaveBeenCalledOnce();
  });

  it.each([
    ['a reply of another type', { type: 'OTHER', sameBuild: true }],
    ['a reply without the answer', { type: 'SAME_BUILD' }],
    ['a non-boolean answer', { type: 'SAME_BUILD', sameBuild: 'true' }],
    ['a string', 'SAME_BUILD'],
    ['null', null],
  ])('is offered on %s', async (_name, reply) => {
    const { isUpdateReady, worker } = await waitingWorkerAnswering(reply);
    await vi.advanceTimersByTimeAsync(0);

    expect(isUpdateReady()).toBe(true);
    expect(worker.postMessage).toHaveBeenCalledOnce();
  });

  it('is offered when the page has no entry script', async () => {
    const registration = new FakeRegistration();
    const { isUpdateReady } = await registered(registration);
    const worker = registration.startInstalling();
    worker.answers({ type: 'SAME_BUILD', sameBuild: true });

    worker.becomes('installed');
    await vi.advanceTimersByTimeAsync(0);

    expect(isUpdateReady()).toBe(true);
    expect(worker.postMessage).not.toHaveBeenCalled();
  });
});

describe('applyUpdate', () => {
  it('asks the waiting worker to take over and reloads once it has', async () => {
    const worker = new FakeWorker('installed');
    const { applyUpdate, container, reloadPage } = await registered(
      new FakeRegistration(worker),
    );

    applyUpdate();
    expect(worker.postMessage).toHaveBeenCalledExactlyOnceWith({
      type: 'SKIP_WAITING',
    });
    expect(reloadPage).not.toHaveBeenCalled();
    container.takeOver();
    container.takeOver();

    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it('leaves a tab that did not accept the update running', async () => {
    const { container, isUpdateReady, reloadPage } = await registered(
      new FakeRegistration(new FakeWorker('installed')),
    );

    container.takeOver();

    expect(reloadPage).not.toHaveBeenCalled();
    expect(isUpdateReady()).toBe(true);
  });

  it('only reloads a tab where the new version already took over', async () => {
    const worker = new FakeWorker('installed');
    const { applyUpdate, container, reloadPage } = await registered(
      new FakeRegistration(worker),
    );
    // Accepted in another tab.
    worker.becomes('activated');
    container.takeOver();

    applyUpdate();

    expect(worker.postMessage).not.toHaveBeenCalled();
    expect(reloadPage).toHaveBeenCalledOnce();
  });

  it('does nothing while no update waits', async () => {
    const { applyUpdate, container, reloadPage } = await registered(
      new FakeRegistration(),
    );

    applyUpdate();
    container.takeOver();

    expect(reloadPage).not.toHaveBeenCalled();
  });
});

describe('the update check', () => {
  it('runs when the page is shown more than a minute after the last one', async () => {
    const registration = new FakeRegistration();
    await registered(registration);

    vi.advanceTimersByTime(MINUTE_MS - 1);
    show();
    expect(registration.update).not.toHaveBeenCalled();

    vi.advanceTimersByTime(2);
    show();
    show();
    expect(registration.update).toHaveBeenCalledOnce();

    vi.advanceTimersByTime(MINUTE_MS - 1);
    show();
    expect(registration.update).toHaveBeenCalledOnce();
  });

  it('runs when the window gets focus, at most once a minute', async () => {
    const registration = new FakeRegistration();
    await registered(registration);

    vi.advanceTimersByTime(MINUTE_MS + 1);
    window.dispatchEvent(new Event('focus'));
    show();

    expect(registration.update).toHaveBeenCalledOnce();
  });

  it('does not run when the page is hidden', async () => {
    const registration = new FakeRegistration();
    await registered(registration);

    vi.advanceTimersByTime(MINUTE_MS + 1);
    hide();

    expect(registration.update).not.toHaveBeenCalled();
  });

  it('logs a failed check', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const registration = new FakeRegistration();
    registration.update.mockImplementation(() =>
      Promise.reject(new TypeError('Failed to fetch')),
    );
    await registered(registration);

    vi.advanceTimersByTime(MINUTE_MS + 1);
    show();
    await vi.runAllTimersAsync();

    expect(warn).toHaveBeenCalledOnce();
  });
});
