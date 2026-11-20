import { fireEvent, renderHook } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import useKeyPress from './useKeyPress';

afterEach(() => {
  document.body.replaceChildren();
});

function element(html: string): HTMLElement {
  const container = document.createElement('div');
  container.innerHTML = html;
  document.body.append(container);
  const found = container.querySelector<HTMLElement>('[data-target]');
  if (!found) throw new Error('No element with data-target');
  return found;
}

it('passes each key and whether it repeats', () => {
  const handler = vi.fn();
  renderHook(() => useKeyPress(handler));

  fireEvent.keyDown(window, { key: '7' });
  fireEvent.keyDown(window, { key: 'ArrowRight', repeat: true });
  expect(handler.mock.calls).toEqual([
    ['7', false],
    ['ArrowRight', true],
  ]);
});

it('hears keys pressed on an element that is not editable', () => {
  const handler = vi.fn();
  renderHook(() => useKeyPress(handler));

  fireEvent.keyDown(element('<button data-target>Next</button>'), {
    key: '8',
  });
  expect(handler).toHaveBeenCalledWith('8', false);
});

it.each(['ctrlKey', 'altKey', 'metaKey'])(
  'ignores keys pressed with %s',
  (modifier) => {
    const handler = vi.fn();
    renderHook(() => useKeyPress(handler));

    fireEvent.keyDown(window, { key: '8', [modifier]: true });
    expect(handler).not.toHaveBeenCalled();
  },
);

it.each([
  ['an input', '<input data-target />'],
  ['a textarea', '<textarea data-target></textarea>'],
  ['a select', '<select data-target><option>One</option></select>'],
  ['a contenteditable element', '<div contenteditable data-target></div>'],
  [
    'an element inside a contenteditable one',
    '<div contenteditable="true"><span data-target>Text</span></div>',
  ],
])('ignores keys typed into %s', (_kind, html) => {
  const handler = vi.fn();
  renderHook(() => useKeyPress(handler));

  fireEvent.keyDown(element(html), { key: '8' });
  expect(handler).not.toHaveBeenCalled();
});

it('hears keys in an element marked as not editable', () => {
  const handler = vi.fn();
  renderHook(() => useKeyPress(handler));

  fireEvent.keyDown(
    element('<div contenteditable="false" data-target></div>'),
    {
      key: '8',
    },
  );
  expect(handler).toHaveBeenCalledWith('8', false);
});

it('listens only while enabled', () => {
  const handler = vi.fn();
  const { rerender } = renderHook(
    ({ enabled }) => useKeyPress(handler, { enabled }),
    { initialProps: { enabled: false } },
  );

  fireEvent.keyDown(window, { key: '8' });
  expect(handler).not.toHaveBeenCalled();

  rerender({ enabled: true });
  fireEvent.keyDown(window, { key: '9' });
  expect(handler).toHaveBeenCalledWith('9', false);
});

it('stops listening when unmounted', () => {
  const handler = vi.fn();
  const { unmount } = renderHook(() => useKeyPress(handler));

  unmount();
  fireEvent.keyDown(window, { key: '8' });
  expect(handler).not.toHaveBeenCalled();
});

it('calls the latest handler', () => {
  const first = vi.fn();
  const second = vi.fn();
  const { rerender } = renderHook(({ handler }) => useKeyPress(handler), {
    initialProps: { handler: first },
  });

  rerender({ handler: second });
  fireEvent.keyDown(window, { key: '8' });
  expect(first).not.toHaveBeenCalled();
  expect(second).toHaveBeenCalledWith('8', false);
});

it('prevents the default action of a key the handler used', () => {
  renderHook(() => useKeyPress((key) => key === 'ArrowRight'));

  const used = new KeyboardEvent('keydown', {
    key: 'ArrowRight',
    cancelable: true,
  });
  const unused = new KeyboardEvent('keydown', { key: 'x', cancelable: true });
  window.dispatchEvent(used);
  window.dispatchEvent(unused);
  expect(used.defaultPrevented).toBe(true);
  expect(unused.defaultPrevented).toBe(false);
});
