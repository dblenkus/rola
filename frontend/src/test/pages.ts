import { screen, waitFor } from '@testing-library/react';
import { expect } from 'vitest';

// Checks that a page whose content failed to load is still a whole page: its
// message inside the page frame, which gives it the page margins, the one
// h1, and the document title, both named by what the page is for.
export async function expectFailedPage(
  title: string,
  message: string,
): Promise<void> {
  const alert = await screen.findByRole('alert');
  expect(alert).toHaveTextContent(message);
  expect(alert.closest('.ui-page')).not.toBeNull();
  const headings = screen.getAllByRole('heading', { level: 1 });
  expect(headings).toHaveLength(1);
  expect(headings[0]).toHaveAccessibleName(title);
  await waitFor(() => expect(document.title).toBe(`${title} · Rola`));
}
