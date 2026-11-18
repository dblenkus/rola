import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import '../../../app/i18n/config';
import type { ImageModel } from '../../../types/models';
import ImageField from './ImageField';

const empty: ImageModel = {
  meta: { id: 1, isChanged: false, isNew: true },
  file: undefined,
  url: '',
  errors: { hasError: false, file: null },
};

// Keeps the selection as the upload store does.
function Field() {
  const [image, setImage] = useState(empty);
  return (
    <ImageField
      image={image}
      handleImageChange={({ file }) =>
        setImage({ ...image, file, url: file ? `blob:${file.name}` : '' })
      }
    />
  );
}

describe('photograph field', () => {
  it('lets a removed photograph be selected again', async () => {
    const user = userEvent.setup();
    render(<Field />);
    const input = screen.getByLabelText<HTMLInputElement>('Select photograph');
    expect(input).toHaveAttribute('accept', 'image/jpeg');

    const photo = new File(['jpeg'], 'photo.jpg', { type: 'image/jpeg' });
    await user.upload(input, photo);
    await user.click(screen.getByRole('button', { name: 'Remove' }));
    expect(input.value).toBe('');
    expect(
      screen.queryByRole('button', { name: 'Remove' }),
    ).not.toBeInTheDocument();
  });

  it('describes the preview by whether a photograph is selected', async () => {
    const user = userEvent.setup();
    render(<Field />);
    expect(
      screen.getByRole('img', { name: 'No photograph selected' }),
    ).toBeInTheDocument();

    const photo = new File(['jpeg'], 'photo.jpg', { type: 'image/jpeg' });
    await user.upload(screen.getByLabelText('Select photograph'), photo);
    expect(
      screen.getByRole('img', { name: 'Selected photograph' }),
    ).toHaveAttribute('src', 'blob:photo.jpg');

    await user.click(screen.getByRole('button', { name: 'Remove' }));
    expect(
      screen.getByRole('img', { name: 'No photograph selected' }),
    ).toBeInTheDocument();
  });
});
