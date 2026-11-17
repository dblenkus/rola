import { AxiosPromise } from 'axios';

import { apiClient } from './Base';
import { Image } from '../types/api';

// RFC 6266: filename* carries the full name percent-encoded, because browsers
// reject header values outside ISO-8859-1, and filename is an ASCII fallback.
function contentDisposition(name: string): string {
  const fallback = name.replace(/[^\x20-\x7E]|["\\]/g, '_');
  // encodeURIComponent throws on an unpaired UTF-16 surrogate, which a file
  // system name can hold. With the u flag a surrogate pair is one code point,
  // so \p{Surrogate} matches only unpaired surrogates.
  const wellFormed = name.replace(/\p{Surrogate}/gu, '\uFFFD');
  const encoded = encodeURIComponent(wellFormed).replace(
    /['()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

export default {
  uploadImage(image: File, authorization?: string): AxiosPromise<Image> {
    return apiClient.post('/file', image, {
      headers: {
        'Content-Type': image.type,
        'Content-Disposition': contentDisposition(image.name),
        ...(authorization === undefined
          ? {}
          : { Authorization: authorization }),
      },
    });
  },
};
