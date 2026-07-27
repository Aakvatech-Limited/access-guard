### Access Guard

Client-side enforcement and logging for ephemeral Frappe site access.

Pairs with [Access Hub](https://github.com/Aakvatech-Limited/access-hub), the issuer app that
mints and signs access grants. See access-hub's
[`docs/DESIGN.md`](https://github.com/Aakvatech-Limited/access-hub/blob/develop/docs/DESIGN.md)
and
[`docs/PROTOCOL.md`](https://github.com/Aakvatech-Limited/access-hub/blob/develop/docs/PROTOCOL.md)
for the shared design and wire protocol (that repo is authoritative for both); this app's own
[`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) covers guard-specific implementation notes.

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app https://github.com/Aakvatech-Limited/access-guard --branch develop
bench install-app access_guard
```

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/access_guard
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### CI

This app can use GitHub Actions for CI. The following workflows are configured:

- CI: Installs this app and runs unit tests on every push to `develop` branch.
- Linters: Runs [Frappe Semgrep Rules](https://github.com/frappe/semgrep-rules) and [pip-audit](https://pypi.org/project/pip-audit/) on every pull request.


### License

mit
