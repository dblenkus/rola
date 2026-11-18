import { describe, expect, it } from 'vitest';
import { serveApi } from '../../test/api';
import { uploadImage } from './api';

async function uploadDisposition(name: string): Promise<string> {
  let disposition: unknown;
  serveApi({
    'POST /file': (config) => {
      disposition = config.headers.get('Content-Disposition');
      return {};
    },
  });
  const file = new File(['jpeg'], name, { type: 'image/jpeg' });
  // The File constructor replaces unpaired surrogates in the name, but
  // File.name is a DOMString, so a file picked from the file system can carry
  // one.
  Object.defineProperty(file, 'name', { value: name });
  await uploadImage(file);
  if (typeof disposition !== 'string') {
    throw new Error('The upload sent no Content-Disposition header');
  }
  return disposition;
}

// Reads the token and quoted-string parameters of a Content-Disposition header
// (RFC 6266) and throws on anything else.
function dispositionParameters(header: string): Map<string, string> {
  const parameter = /;\s*([^\s;=]+)=(?:"((?:[^"\\]|\\.)*)"|([^\s;"]+))\s*/y;
  parameter.lastIndex = header.search(/;|$/);
  const parameters = new Map<string, string>();
  while (parameter.lastIndex < header.length) {
    const start = parameter.lastIndex;
    const match = parameter.exec(header);
    if (!match) {
      throw new Error(`Cannot parse ${header.slice(start)} in ${header}`);
    }
    const [, name = '', quoted, token = ''] = match;
    parameters.set(
      name.toLowerCase(),
      quoted === undefined ? token : quoted.replace(/\\(.)/g, '$1'),
    );
  }
  return parameters;
}

// RFC 5987 ext-value: charset'language'value, where value percent-encodes
// every character outside attr-char.
function decodeExtValue(value: string | undefined): string {
  const encoded = /^UTF-8'[\w-]*'((?:[\w!#$&+.^`|~-]|%[\dA-F]{2})*)$/i.exec(
    value ?? '',
  )?.[1];
  if (encoded === undefined) {
    throw new Error(`Not a UTF-8 RFC 5987 value: ${value}`);
  }
  return decodeURIComponent(encoded);
}

describe('photograph upload file names', () => {
  it('sends a plain name as both the fallback and the full name', async () => {
    expect(await uploadDisposition('photo.jpg')).toBe(
      `attachment; filename="photo.jpg"; filename*=UTF-8''photo.jpg`,
    );
  });

  describe.each([
    'photo.jpg',
    'Žaba v soncu.jpg',
    'čšž.jpg',
    'photo;1.jpg',
    'my "best".jpg',
    "it's (1)*.jpg",
    'back\\slash\nnewline.jpg',
  ])('uploading %j', (name) => {
    // HTTP treats header bytes outside US-ASCII as opaque (RFC 9110), and axios
    // silently strips control characters and anything outside ISO-8859-1.
    it('sends only printable ASCII', async () => {
      expect(await uploadDisposition(name)).toMatch(/^[\x20-\x7E]+$/);
    });

    // The backend reads the name from filename* and rejects a name without an
    // extension.
    it('sends the full name in filename*', async () => {
      const parameters = dispositionParameters(await uploadDisposition(name));
      expect(decodeExtValue(parameters.get('filename*'))).toBe(name);
    });

    it('keeps the extension in the filename fallback', async () => {
      const parameters = dispositionParameters(await uploadDisposition(name));
      expect(parameters.get('filename')).toMatch(/\.jpg$/);
    });
  });

  // An unpaired UTF-16 surrogate has no UTF-8 encoding.
  it('replaces only unpaired surrogates with U+FFFD', async () => {
    const parameters = dispositionParameters(
      await uploadDisposition('\u{1F4F7}\uD800.jpg'),
    );
    expect(decodeExtValue(parameters.get('filename*'))).toBe(
      '\u{1F4F7}\uFFFD.jpg',
    );
    expect(parameters.get('filename')).toMatch(/\.jpg$/);
  });
});
