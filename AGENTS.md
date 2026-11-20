# Rola

Rola runs photography contests: entrants register and upload photographs,
juries rate them, and the results are published. The repository holds a
Django and Django REST framework backend (`backend/`, the `rola` Python
distribution) and a React, Redux Toolkit and Vite frontend (`frontend/`).
The frontend calls the API under `/api/v1` on its own origin; organizers use
the Django admin under `/django-admin/`. `docs/` is the Sphinx documentation.

## Backend layout

`backend/rola/` holds one Django app per domain, plus the project
configuration:

- `config/`: settings (`settings.py`, `test_settings.py`, `environment.py`),
  `urls.py`, `wsgi.py`. Not an app.
- `common/`: `BaseModel`, `BaseSerializer`, the shared permissions, ordering
  filter and pagination, and the `readinesscheck` command.
- `accounts/`: users, login tokens, registration, activation, password
  resets and account emails; the password change that the password reset
  and the admin share (`services.py`); the admin site (`sites.py`) and its
  password-change form (`forms.py`).
- `contests/`: what an organizer sets up: Contest, Theme, Institution.
- `entries/`: what an entrant submits: Author, SubmissionSet, Submission and
  File (a photograph), with `photos.py` (validation, metadata stripping,
  thumbnails, file names), `archive.py` (the contest download) and
  `services.py` (the upload rules).
- `payments/`: payments, and `PAID_SUBMISSION`, the one "paid submission"
  filter.
- `judging/`: judges, ratings, theme results and rewards.
- `locale/`: the Slovenian catalogue.

Each app imports only from the apps before it in this order:
`common` → `accounts` → `contests` → `entries` → `payments` → `judging`.
`config` composes them. Where an earlier app's feature needs a later app, the
later app adds it: `entries/admin.py` adds the contest download to the
contest admin.

Inside an app:

- `models.py`: models, and a `QuerySet` whose methods name the rules
  (`Contest.objects.in_judging()`, `.results_published()`). Filter by those
  methods instead of repeating date comparisons.
- `services.py`: writes that enforce rules across models, and the entry
  rules that the API checks (`entries/services.py`'s
  `require_open_contest`).
- `api/`: `serializers.py`, `views.py`, `filters.py` and `permissions.py` as
  the app needs them, and `routes.py`, whose `register(router)` adds the
  app's endpoints.
  `config/urls.py` calls each app's `register`. `accounts/api/` also holds
  `authentication.py` (the token authentication) and `throttling.py` (the
  rate limits, which the admin login and password change in `sites.py`
  share too).
- `admin.py`, `management/commands/`, `migrations/0001_schema.py`.

Tests live in `backend/tests/<app>/` (`accounts`, `contests`, `entries`,
`payments`, `judging`, and `project/` for settings, schema, migrations and
query counts), with factories and shared helpers in `tests/factories.py` and
fixtures in `tests/conftest.py`.

## Frontend layout

`frontend/src/`:

- `design/`: the design system. `tokens.json` and `components.css` (its
  `rl-` classes) are vendored; `tokens.css` is generated from `tokens.json`;
  `layers.css` (the cascade layers, `base` below `design-system`, which holds
  `tokens.css` and `components.css`), `fonts.css` (self-hosted Inter and DM
  Mono), `app.css` (app-wide rules, the element defaults in `base`, and the
  breakpoints, `width < 40rem` and `width >= 64rem`), `logos/`. `tokens.css`
  declares each colour for the light and the dark theme: light on `:root`
  and `[data-theme="light"]`, dark on `[data-theme="dark"]` and, on a dark
  device, on a root without the attribute. All other
  CSS is unlayered, so an app rule beats a vendored one whatever its
  specificity or the order the build links the files in; keep it that way.
- `app/`: `main.tsx`, `App.tsx` (picks the layout per route), `routes.tsx`
  (every route, each page `React.lazy` in its own Suspense boundary;
  `preloadPages()` for tests), `store.ts` (the Redux store, which also
  registers the API client's unexpected-failure handler), `layout/`
  (`StandardLayout`, `BareLayout` for the judge's scoring view, `AppBar`,
  `MainNav`, `LanguageSwitch`, `AccountMenu`), `appearance/` (the choice of
  System, Light or Dark: storage, `data-theme` on `<html>`, other tabs;
  `public/appearance.js` applies it before the first paint), `NotFound.tsx`,
  `RouteErrorBoundary.tsx`, `RouteFocus.tsx`, `AriaProviders.tsx`, `pwa/`
  (worker registration, update prompt, offline notice, and what `sw.ts`
  imports: `serverPaths.ts`, `navigationHandler.ts`,
  `workerMessageHandler.ts` and the messages in `workerMessages.ts`, which
  use no DOM-only or worker-only globals), `i18n/` (`locales/en` and
  `locales/sl`), `sentry.ts`.
- `shared/`: `api/` (the axios `client.ts`, `errors.ts`, `token.ts`,
  pagination, `types.ts` and the generated `generated-api.ts`), `ui/` (the
  kit on React Aria Components: `Button`, `TextField`, `Page`, `Table`, …),
  `hooks/`, `utils/`.
- `features/<feature>/`: `auth`, `contests`, `upload`, `jury`, `results`,
  `admin`, `notifications`. Each has an `api.ts` of named functions, and as
  needed `components/`, `pages/` and `state/` (`reducer.ts` holds the slice,
  `actions.ts` the thunks and selectors).
- `test/`: fixtures, API mocks, setup and app test helpers. Tests sit next to
  the code they cover as `*.test.ts(x)`.
- `sw.ts`: the service worker, built by `vite-plugin-pwa`.

Import rule, enforced by the local rules in `eslint.config.js`:
`shared/` imports nothing from `app/` or `features/`, and a feature imports
another feature only through that feature's `index.ts`. `app/` may import
any feature file.

Styling: the design system's classes and tokens, no MUI or CSS-in-JS. A
component's CSS sits beside it, with classes prefixed `ui-` in `shared/ui/`,
`shell-` in `app/layout/`, `pwa-` in `app/pwa/`, and the feature's name in a
feature (`upload-`, `jury-`, …). Colours are tokens, never literals, and
every page works in both themes. The dark theme turns the swatches around
(`--ink` is light there, `--paper` dark); what must keep the light values,
as the judge's scoring view does, sits inside `data-theme="light"`. In code
and in the interface the setting is the "appearance": a theme is part of a
contest.

## Where new code goes

- Model: the domain app's `models.py`, in the earliest app of the order that
  the model fits. A rule about which rows qualify: a method on that model's
  `QuerySet`.
- Rule on writes: the app's `services.py`, called from the view. Access rule:
  the app's `api/permissions.py`.
- Endpoint: a viewset in the app's `api/views.py` with its serializer, and a
  line in the app's `api/routes.py`.
- Management command: the app's `management/commands/`.
- Page: `features/<feature>/pages/`, with one `h1` and a document title
  (`shared/ui/Page`, or `shared/hooks/usePageTitle`) and its CSS beside it,
  and a lazy entry in `app/routes.tsx`'s `pageRoutes`. A path that the
  server must answer instead of the app also goes into
  `app/pwa/serverPaths.ts`, `frontend/docker/default.conf` and the
  development proxy in `vite.config.ts`.
- Shared component: `shared/ui/`, on React Aria Components where it is
  interactive, styled with the design system's classes and its own `ui-`
  CSS.
- User-visible string: a key in both `app/i18n/locales/en` and
  `locales/sl`.
- API call: a named function in `features/<feature>/api.ts` that uses
  `apiClient` from `shared/api/client.ts` and the types in
  `shared/api/types.ts`. Export it from the feature's `index.ts` if another
  feature needs it.
- Code that two features need and that knows no feature: `shared/`.

## Commands

From the repository root, with the uv and Node.js versions that
`docs/contributing.rst` names. With another uv, add
`UV="uvx --from uv==<that version> uv"` to every `make` command.

- `make backend-sync` and `make frontend-install`: install the dependencies.
- `make check`: lint, formatting, types, tests on SQLite and PostgreSQL,
  system checks, migration check, docs, frontend checks, and the API
  contract regeneration. The PostgreSQL tests start the Compose `db` service.
- One part: `make backend-test`, `make backend-test-postgresql`,
  `make backend-lint`, `make backend-format`, `make backend-types`,
  `make docs`, `make frontend-test`, `make frontend-lint`, `make api-contract`.
- From `frontend/`: `npm run tokens` regenerates `src/design/tokens.css`.
- The whole stack: `docker compose up --build --wait`, then
  http://localhost:8080.

`docs/contributing.rst` describes each check and the maintenance tasks.

## Invariants

- `backend/openapi.yaml` and `frontend/src/shared/api/generated-api.ts` are
  generated. After a serializer, view or schema change, run
  `make api-schema api-types` and commit both files with the change; CI fails
  on any difference. List an API change in `docs/CHANGELOG.rst`.
- Each app has one migration, `0001_schema`, until the first production
  deployment. A model change regenerates that app's `0001_schema` in the same
  commit, as `docs/contributing.rst` describes, instead of adding a
  migration. Keep `CryptoExtension()` first in judging's.
- A behaviour change comes with a test that fails without it. Do not edit an
  existing test's assertions to fit a change that should not alter
  behaviour.
- Ruff's docstring rules apply to all backend code outside `tests/` and
  `migrations/`. mypy checks the whole `rola` package. The strict override in
  `backend/pyproject.toml` lists the strict flags one by one, because mypy
  applies `strict = true` in an override to every module; add a new strict
  module to that override's list.
- `frontend/src/design/components.css` and `tokens.css` are not edited by
  hand. A change to `tokens.json` regenerates `tokens.css` in the same
  commit; `npm run build` fails otherwise.
- `data-theme` is only ever `light` or `dark`, and "system" is the attribute
  absent. The storage key `rola.appearance` and those two values never
  change: an installed service worker can serve an older
  `public/appearance.js` to a newer page.
- The service worker caches only the build's own files, never API responses
  or photographs, and gets documents from the network whenever it can be
  reached: every document carries its own script policy nonce.
- The DOM does not depend on the viewport width: layouts respond through CSS
  only. jsdom cannot test them; check layout changes by hand as
  `docs/contributing.rst` describes.
- The repository is public: no internal links or customer names in code,
  commits or pull requests.
