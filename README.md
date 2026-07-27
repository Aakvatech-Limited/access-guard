### Access Guard

Client-side enforcement and logging for ephemeral Frappe site access.

Pairs with [Access Hub](https://github.com/Aakvatech-Limited/access-hub), the issuer app that
mints and signs access grants. The **access-hub** repo is authoritative for the shared docs —
[`docs/DESIGN.md`](https://github.com/Aakvatech-Limited/access-hub/blob/develop/docs/DESIGN.md)
(design + rationale),
[`docs/PROTOCOL.md`](https://github.com/Aakvatech-Limited/access-hub/blob/develop/docs/PROTOCOL.md)
(wire contract), and
[`docs/OPERATIONS.md`](https://github.com/Aakvatech-Limited/access-hub/blob/develop/docs/OPERATIONS.md)
(install/enroll/use). This app's own [`docs/GUARD_NOTES.md`](docs/GUARD_NOTES.md) covers
guard-specific implementation notes.

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
