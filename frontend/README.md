# Rola frontend

The React frontend of Rola, built with Vite. It needs Node.js 26.13.0, the
version in `.node-version`. npm installs only releases that are at least 7
days old (`.npmrc`).

## Development

```shell
npm ci
npm run dev
```

The development server listens on http://localhost:5173 and forwards `/api`,
`/core`, `/django-admin`, `/media` and `/static2` to the backend on
http://localhost:8000; set `API_PROXY_TARGET` for another address. The
repository's Compose development stack runs it together with the backend on
http://localhost:8080.

Two variables are read at build time, from the environment or a `.env` file
in this directory:

- `VITE_PAYPAL_CLIENT_ID`: the PayPal client id. Without it, the
  confirmation page shows an error instead of the PayPal buttons.
- `VITE_SENTRY_DSN`: the Sentry DSN for error reports. Without it, nothing
  is reported.

Production builds require both.

## Scripts

- `npm run build`: type-check and build into `dist/`.
- `npm test`: run the tests once; `npm run test:watch` keeps running them.
- `npm run lint`: ESLint.
- `npm run typecheck`: TypeScript.
- `npm run format` and `npm run format:check`: Prettier.
- `npm run api:generate`: regenerate `src/types/generated-api.ts` from
  `../backend/openapi.yaml`.

The repository's `docs/contributing.rst` lists the checks that CI runs.
