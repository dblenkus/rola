// Groups items by a numeric key, in ascending key order. Each group keeps the
// items' original order.
export default function groupBy<T>(
  items: readonly T[],
  key: (item: T) => number,
): [T, ...T[]][] {
  const groups = new Map<number, [T, ...T[]]>();
  for (const item of items) {
    const value = key(item);
    const group = groups.get(value);
    if (group) {
      group.push(item);
    } else {
      groups.set(value, [item]);
    }
  }
  return [...groups].sort(([a], [b]) => a - b).map(([, group]) => group);
}
