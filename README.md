# Rola

Rola runs photography contests: entrants register and upload photographs,
juries rate them, and the results are published.

## Development

Docker with Compose runs the whole application from the repository root:

```shell
docker compose up --build --wait
```

The site is then on http://localhost:8080 and the Django admin on
http://localhost:8080/django-admin/. Create an admin account with:

```shell
docker compose exec backend python manage.py createsuperuser
```

`make check` runs the checks that CI runs; the `Makefile` lists them one by
one. [docs/contributing.rst](docs/contributing.rst) covers native
development, the checks, and how to regenerate migrations, the API contract
and the lockfiles. [AGENTS.md](AGENTS.md) describes the code layout and where
new code goes.

## Layout

- `backend/`: the Django backend, one Python distribution
  ([backend/README.rst](backend/README.rst)).
- `frontend/`: the React frontend ([frontend/README.md](frontend/README.md)).
- `compose.yaml`: the development stack. `compose.production.yaml`: the
  production stack ([docs/deployment.rst](docs/deployment.rst)).
- `docs/`: the Sphinx documentation, including the one-off
  [data transfer](docs/transfer.rst) from the previous deployment, and
  [docs/CHANGELOG.rst](docs/CHANGELOG.rst).

## Licences

| Code | Licence | Text |
| --- | --- | --- |
| Code from the Rolca contest, payment and rating apps | Apache-2.0 | [backend/licenses/Apache-2.0.txt](backend/licenses/Apache-2.0.txt) |
| Code from the drf_user account app | BSD-3-Clause | [backend/licenses/BSD-3-Clause.txt](backend/licenses/BSD-3-Clause.txt) |
| everything else | AGPL-3.0-only | [LICENSE](LICENSE) |

[backend/licenses/README.rst](backend/licenses/README.rst) names the modules
that the inherited code is in. `backend/LICENSE-AGPL` is a copy of `LICENSE`,
so that the backend wheel ships all three texts. The wheel declares
`AGPL-3.0-only AND Apache-2.0 AND BSD-3-Clause`.
