# Rola frontend

The React frontend of Rola, built with Vite on Rola's design system, with
components on React Aria Components. It needs Node.js 26.13.0, the version
in `.node-version`. npm installs only releases that are at least 7 days old
(`.npmrc`).

## Development

```shell
npm ci
npm run dev
```

The development server listens on http://localhost:5173 and forwards `/api`,
`/django-admin`, `/media` and `/static2` to the backend on
http://localhost:8000; set `API_PROXY_TARGET` for another address. The
repository's Compose development stack runs it together with the backend on
http://localhost:8080. Only a production build registers the service worker.

One variable is read at build time, from the environment or a `.env` file
in this directory: `VITE_SENTRY_DSN`, the Sentry DSN for error reports.
Without it, nothing is reported. Production builds require it.

## Structure

- `src/design/`: the design system. `tokens.json` and `components.css` come
  from it and are not edited here; `tokens.css` is generated from
  `tokens.json`. `fonts.css` declares Inter and DM Mono, served from the
  site by `@fontsource-variable/inter` and `@fontsource/dm-mono` in their
  latin and latin-ext subsets, with no request to Google Fonts. `app.css`
  holds the app-wide rules and names the two breakpoints. `layers.css`
  declares the cascade layers: `base` for `app.css`'s element defaults, then
  `design-system` for `tokens.css` and `components.css`. Every other rule is
  unlayered and beats both, whatever its specificity and file order.
- `src/shared/ui/`: the component kit, each component with its CSS beside it.
- `src/app/`: the shell, the routes, the store, the translations, and in
  `pwa/` the service worker's registration and the handlers it imports.
- `src/features/<feature>/`: each feature's API calls, pages and state.
- `src/sw.ts`: the service worker, built with `vite-plugin-pwa`.
- `scripts/`: `build-tokens.ts`, which writes `tokens.css`, and the tests
  of the design files.

The root `AGENTS.md` describes the layout and its rules in more detail.

## Scripts

- `npm run build`: check `tokens.css`, type-check, and build into `dist/`.
- `npm test`: run the tests once, as two Vitest projects: `app` in jsdom and
  `scripts` in Node.js. `npm run test:watch` keeps running them.
- `npm run lint`: ESLint.
- `npm run typecheck`: TypeScript.
- `npm run format` and `npm run format:check`: Prettier.
- `npm run tokens`: write `src/design/tokens.css` from `tokens.json`;
  `npm run tokens:check` fails while it is out of date.
- `npm run api:generate`: regenerate `src/shared/api/generated-api.ts` from
  `../backend/openapi.yaml`.

The repository's `docs/contributing.rst` lists the checks that CI runs, the
layout check by hand, and how to update the design system and the
dependencies.
