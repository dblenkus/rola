# The checks that CI runs, one target per CI step; docs/contributing.rst
# describes them. `make check` runs those that a change usually needs.
#
# With another uv than the one docs/contributing.rst names:
#   make UV="uvx --from uv==<that version> uv" <target>

UV ?= uv
DOCS_BUILD ?= docs/_build/html
AUDIT_REQUIREMENTS ?= $(or $(TMPDIR),/tmp)/rola-audit.txt

# The settings refuse to load without these. CI sets its own values in the
# environment, which take precedence; the database is the development stack's.
export ROLA_SECRET_KEY ?= check-only-secret-key
export ROLA_FRONTEND_URL ?= http://localhost:8080
export ROLA_POSTGRESQL_HOST ?= 127.0.0.1
export ROLA_POSTGRESQL_PORT ?= 55432
export ROLA_POSTGRESQL_PASSWORD ?= rola

.PHONY: check backend frontend db \
	backend-sync backend-lock-check backend-test backend-test-postgresql \
	backend-system-check backend-migrations-check backend-migrate \
	backend-lint backend-format backend-types backend-audit docs \
	api-schema api-types api-contract \
	frontend-install frontend-lint frontend-format frontend-typecheck \
	frontend-test frontend-build frontend-deps frontend-audit \
	actionlint dependabot-config

check: backend frontend api-contract

backend: backend-lint backend-format backend-types backend-test \
	backend-test-postgresql backend-system-check backend-migrations-check docs

frontend: frontend-lint frontend-format frontend-typecheck frontend-test \
	frontend-build

# PostgreSQL of the development stack, on 127.0.0.1:55432.
db:
	docker compose -f compose.yaml up -d --wait db

backend-sync:
	cd backend && $(UV) sync --locked --all-groups

backend-lock-check:
	cd backend && $(UV) lock --check

backend-test:
	cd backend && $(UV) run pytest

backend-test-postgresql: db
	cd backend && ROLA_TEST_POSTGRESQL=true $(UV) run pytest

backend-system-check:
	cd backend && $(UV) run python manage.py check

backend-migrations-check:
	cd backend && $(UV) run python manage.py makemigrations --check --dry-run

# Migrates the database that ROLA_POSTGRESQL_NAME names, rola by default.
# CI runs it on an empty database.
backend-migrate: db
	cd backend && $(UV) run python manage.py migrate --noinput
	cd backend && $(UV) run python manage.py createcachetable
	cd backend && $(UV) run python manage.py readinesscheck

backend-lint:
	cd backend && $(UV) run ruff check .
	cd backend && $(UV) run ruff check --config pyproject.toml ../docs/conf.py

backend-format:
	cd backend && $(UV) run ruff format --check .
	cd backend && $(UV) run ruff format --check --config pyproject.toml ../docs/conf.py

backend-types:
	cd backend && $(UV) run mypy

backend-audit:
	cd backend && $(UV) export --frozen --no-dev --no-hashes --no-emit-project \
		-o "$(AUDIT_REQUIREMENTS)"
	cd backend && $(UV) tool run --exclude-newer "7 days" --from pip-audit==2.10.1 \
		pip-audit -r "$(AUDIT_REQUIREMENTS)" --no-deps --disable-pip

docs:
	cd backend && $(UV) run sphinx-build -W --keep-going -b html ../docs \
		"$(abspath $(DOCS_BUILD))"

# drf-spectacular takes integer bounds from the database backend, so the schema
# is generated with the production settings, which select PostgreSQL. No
# database server needs to run.
api-schema:
	cd backend && $(UV) run python manage.py spectacular --file openapi.yaml \
		--validate --fail-on-warn

api-types:
	cd frontend && npm run api:generate

# One after the other: api-types reads the schema that api-schema writes.
api-contract:
	$(MAKE) api-schema
	$(MAKE) api-types
	git diff --exit-code -- backend/openapi.yaml frontend/src/shared/api/generated-api.ts

frontend-install:
	cd frontend && npm ci

frontend-lint:
	cd frontend && npm run lint

frontend-format:
	cd frontend && npm run format:check

frontend-typecheck:
	cd frontend && npm run typecheck

frontend-test:
	cd frontend && npm test

frontend-build:
	cd frontend && npm run build

frontend-deps:
	cd frontend && npm ls --all

frontend-audit:
	cd frontend && npm audit --omit=dev

actionlint:
	docker run --rm -v "$(CURDIR)":/repo -w /repo rhysd/actionlint:1.7.12

dependabot-config:
	$(UV) tool run --exclude-newer "7 days" --from check-jsonschema==0.39.0 \
		check-jsonschema --builtin-schema vendor.dependabot .github/dependabot.yml
