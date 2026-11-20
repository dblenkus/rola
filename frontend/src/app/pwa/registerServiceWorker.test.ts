import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Reloading is the browser navigation the module ends in; jsdom has none.
vi.mock('./reloadPage', () => ({ reloadPage: vi.fn() }));

const MINUTE_MS = 60 * 1000;

class FakeWorker extends EventTarget {
  state: ServiceWorkerState;
  postMessage = vi.fn();

  constructor(state: ServiceWorkerState) {
    super();
    this.state = state;
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

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-11-20T10:00:00Z'));
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, 'serviceWorker');
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

    dismissUpdate();
    expect(isUpdateReady()).toBe(false);
    registration.startInstalling().becomes('installed');

    expect(isUpdateReady()).toBe(true);
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
