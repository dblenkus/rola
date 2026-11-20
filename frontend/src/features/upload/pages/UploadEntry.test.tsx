import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../app/i18n/config';
import store from '../../../app/store';
import { serveApi, signIn } from '../../../test/api';
import { open } from '../../../test/app';
import { contest } from '../../../test/fixtures';
import type { Contest } from '../../../shared/api/types';
import { formatDate } from '../../../shared/utils/formatDate';
import { uploadReset } from '../state/actions';

// The pixel size the next decoded photograph has; jsdom decodes nothing.
let decodedSize = { width: 3000, height: 2000 };

class DecodedImage {
  width = decodedSize.width;
  height = decodedSize.height;
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  #src = '';

  get src(): string {
    return this.#src;
  }

  set src(value: string) {
    this.#src = value;
    queueMicrotask(() => this.onload?.());
  }
}

// A date `days` from today as the API sends a date-only value.
function inDays(days: number): string {
  const date = new Date();
  date.setDate(date.getDate() + days);
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

function photograph(name: string): File {
  return new File(['jpeg'], name, { type: 'image/jpeg' });
}

function openForm(served: Contest = contest): void {
  serveApi({ 'GET /contest/1': () => served });
  open('/contest/1/upload');
}

// The entry row of a photograph slot, by its title field's or photograph's
// position in the theme's list.
function row(index: number): HTMLElement {
  const rows = within(screen.getByRole('main')).getAllByRole('listitem');
  const found = rows[index];
  if (!found) {
    throw new Error(`There is no entry row ${index}`);
  }
  return found;
}

beforeEach(() => {
  localStorage.clear();
  signIn();
  decodedSize = { width: 3000, height: 2000 };
  vi.stubGlobal('Image', DecodedImage);
  store.dispatch(uploadReset());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('upload page header', () => {
  it('names the page by the contest and links back to it', async () => {
    openForm();
    const heading = await screen.findByRole('heading', {
      level: 1,
      name: contest.title,
    });
    expect(heading).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    await waitFor(() => expect(document.title).toBe(`${contest.title} · Rola`));
    expect(
      screen.getByRole('link', { name: 'Back to contest' }),
    ).toHaveAttribute('href', '/contest/1/details');
  });

  it('says when entries close and how many days are left', async () => {
    const endDate = inDays(12);
    openForm({ ...contest, end_date: endDate });
    await screen.findByRole('heading', { level: 1, name: contest.title });
    const [year, month, day] = endDate.split('-').map(Number);
    // The page writes the date with no-break spaces, which text matching
    // reads as spaces.
    const date = formatDate(
      new Date(year ?? 0, (month ?? 1) - 1, day ?? 1),
      'en',
    ).replace(/\s/g, ' ');
    const deadline = screen.getByText('Entries close', { exact: false });
    expect(deadline).toHaveTextContent(`Entries close ${date} · 12 days left`);
    expect(within(deadline).getByText(date).tagName).toBe('STRONG');
  });
});

describe('theme section', () => {
  it('counts the selected photographs against the theme limit', async () => {
    const user = userEvent.setup();
    openForm();
    const theme = (
      await screen.findByRole('heading', { level: 2, name: 'Nature' })
    ).closest('section');
    if (!theme) {
      throw new Error('The theme has no section');
    }
    expect(within(theme).getByText('0 of 2 photos')).toBeInTheDocument();
    expect(
      within(theme).getByText(
        'JPEG · long edge 2500–3500 px · max. 5 MB · up to 2 photos',
      ),
    ).toBeInTheDocument();
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('harbour.jpg'));
    expect(await within(theme).findByText('1 of 2 photos')).toBeInTheDocument();
  });

  it('lists a series under one title and description', async () => {
    openForm({
      ...contest,
      themes: contest.themes.map((theme) => ({
        ...theme,
        is_series: true,
        n_photos: 3,
      })),
    });
    expect(
      await screen.findByText(
        'JPEG · long edge 2500–3500 px · max. 5 MB · a series of 2 to 3 photos',
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByLabelText('Select photograph')).toHaveLength(3);
    expect(
      screen
        .getAllByRole('textbox', { name: /title/i })
        .map((field) => field.getAttribute('name') ?? ''),
    ).toEqual(['title']);
    expect(screen.getByRole('textbox', { name: 'Title' })).toBeInTheDocument();
    expect(
      screen.getByRole('textbox', { name: 'Description' }),
    ).toBeInTheDocument();
  });
});

describe('entry row', () => {
  it('shows an empty slot with its number', async () => {
    openForm();
    const field = await screen.findByRole('textbox', {
      name: 'Title of photo 01',
    });
    const empty = row(0);
    expect(empty).toContainElement(field);
    expect(
      within(empty).getByRole('img', { name: 'No photograph selected' }),
    ).toBeInTheDocument();
    expect(within(empty).getByText('01')).toBeInTheDocument();
    expect(
      within(empty).getByRole('button', { name: 'Select' }),
    ).toBeInTheDocument();
    expect(
      within(empty).queryByRole('img', { name: 'OK' }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('textbox', { name: 'Title of photo 02' }),
    ).toBeInTheDocument();
  });

  it('shows the selected photograph with its size and orientation', async () => {
    const user = userEvent.setup();
    openForm();
    await screen.findByRole('textbox', { name: 'Title of photo 01' });
    const [first, second] = screen.getAllByLabelText('Select photograph');
    if (!first || !second) {
      throw new Error('The form has fewer than two photograph inputs');
    }
    await user.upload(first, photograph('harbour.jpg'));
    // The first photograph decodes asynchronously; it must have decoded
    // before the next decode size applies.
    expect(
      await within(row(0)).findByRole('img', { name: 'Photo 01, landscape' }),
    ).toBeInTheDocument();
    expect(within(row(0)).getByText('3000 × 2000 px')).toBeInTheDocument();
    decodedSize = { width: 2000, height: 3000 };
    await user.upload(second, photograph('tower.jpg'));

    expect(
      await within(row(0)).findByRole('img', { name: 'Photo 01, landscape' }),
    ).toBeInTheDocument();
    expect(within(row(0)).getByText('3000 × 2000 px')).toBeInTheDocument();
    expect(
      await within(row(1)).findByRole('img', { name: 'Photo 02, portrait' }),
    ).toBeInTheDocument();
    expect(within(row(1)).getByText('2000 × 3000 px')).toBeInTheDocument();
    expect(
      within(row(0)).getByRole('button', { name: 'Change' }),
    ).toBeInTheDocument();
    expect(
      within(row(0)).getByRole('button', { name: 'Remove' }),
    ).toBeInTheDocument();
  });

  it('marks a titled photograph within the limits as OK', async () => {
    const user = userEvent.setup();
    openForm();
    const title = await screen.findByRole('textbox', {
      name: 'Title of photo 01',
    });
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('harbour.jpg'));
    await within(row(0)).findByRole('img', { name: 'Photo 01, landscape' });
    expect(
      within(row(0)).queryByRole('img', { name: 'OK' }),
    ).not.toBeInTheDocument();

    await user.type(title, 'Harbour at dawn');
    expect(within(row(0)).getByRole('img', { name: 'OK' })).toBeInTheDocument();
  });

  it('marks no photograph outside the limits as OK', async () => {
    const user = userEvent.setup();
    decodedSize = { width: 1600, height: 1067 };
    openForm();
    const title = await screen.findByRole('textbox', {
      name: 'Title of photo 01',
    });
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('small.jpg'));
    await user.type(title, 'Small harbour');
    expect(await within(row(0)).findByText('1600 × 1067 px')).toBeVisible();
    expect(
      within(row(0)).queryByRole('img', { name: 'OK' }),
    ).not.toBeInTheDocument();
  });

  it('marks a missing title on its field', async () => {
    const user = userEvent.setup();
    openForm();
    await user.type(
      await screen.findByRole('textbox', { name: /first name/i }),
      'Ana',
    );
    await user.type(
      screen.getByRole('textbox', { name: /last name/i }),
      'Novak',
    );
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('harbour.jpg'));
    await within(row(0)).findByRole('img', { name: 'Photo 01, landscape' });
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    const title = await screen.findByRole('textbox', {
      name: 'Title of photo 01',
      description: 'Please enter title.',
    });
    expect(title).toHaveAttribute('aria-invalid', 'true');
    expect(
      within(row(0)).queryByRole('img', { name: 'OK' }),
    ).not.toBeInTheDocument();
  });

  it('puts a file problem beside the action that fixes it', async () => {
    const user = userEvent.setup();
    decodedSize = { width: 1600, height: 1067 };
    openForm();
    const title = await screen.findByRole('textbox', {
      name: 'Title of photo 01',
    });
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('small.jpg'));
    await user.type(title, 'Small harbour');
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(
      await within(row(0)).findByRole('button', {
        name: 'Change',
        description: 'Long edge should be at least 2500px.',
      }),
    ).toBeInTheDocument();
    expect(title).not.toHaveAttribute('aria-invalid');
    expect(
      screen.getByText('Please fix errors before uploading.'),
    ).toBeInTheDocument();
  });
});

describe('submit bar', () => {
  it('says the upload runs while it runs', async () => {
    const user = userEvent.setup();
    serveApi({
      'GET /contest/1': () => ({ ...contest, end_date: inDays(30) }),
      // The upload never finishes in this test.
      'POST /file': () => new Promise(() => undefined),
    });
    open('/contest/1/upload');
    await user.type(
      await screen.findByRole('textbox', { name: /first name/i }),
      'Ana',
    );
    await user.type(
      screen.getByRole('textbox', { name: /last name/i }),
      'Novak',
    );
    const [first] = screen.getAllByLabelText('Select photograph');
    if (!first) {
      throw new Error('The form has no photograph input');
    }
    await user.upload(first, photograph('harbour.jpg'));
    await user.type(
      screen.getByRole('textbox', { name: 'Title of photo 01' }),
      'Harbour at dawn',
    );
    expect(
      screen.getByText(
        `You can delete your entry under Edit submissions until`,
        { exact: false },
      ),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Upload' }));

    expect(
      await screen.findByRole('progressbar', { name: 'Uploading photographs' }),
    ).not.toHaveAttribute('aria-valuenow');
    expect(
      screen.queryByRole('button', { name: 'Upload' }),
    ).not.toBeInTheDocument();
  });
});

describe('design system', () => {
  it('renders no MUI component on the upload page', async () => {
    openForm({ ...contest, dob_required: true, school_show: true });
    await screen.findByRole('heading', { level: 1, name: contest.title });
    await waitFor(() =>
      expect(document.querySelector('[class*="Mui"]')).toBeNull(),
    );
  });
});
