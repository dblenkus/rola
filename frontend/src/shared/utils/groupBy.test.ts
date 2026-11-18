import { describe, expect, it } from 'vitest';
import groupBy from './groupBy';

describe('grouping by a numeric key', () => {
  it('orders groups by ascending key and keeps the item order', () => {
    const items = [
      { key: 9, name: 'a' },
      { key: 4, name: 'b' },
      { key: 9, name: 'c' },
      { key: 10, name: 'd' },
    ];
    expect(groupBy(items, ({ key }) => key)).toEqual([
      [{ key: 4, name: 'b' }],
      [
        { key: 9, name: 'a' },
        { key: 9, name: 'c' },
      ],
      [{ key: 10, name: 'd' }],
    ]);
  });

  it('returns no groups for no items', () => {
    expect(groupBy([], () => 1)).toEqual([]);
  });
});
