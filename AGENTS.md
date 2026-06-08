# Agent routing index

Explore the repository directly. This file routes agents to project sources; it
is not a substitute for contributor documentation.

## Workflow

- Put plans, notes, and other ephemeral files in the ignored `.tmp/` directory.
- For non-trivial work, inspect `pyproject.toml`, `tox.ini`,
  `.pre-commit-config.yaml`, `requirements.txt`, and `test-requirements.txt`.
- Run tests through `tox` or `stestr` as configured in `tox.ini`; do not use
  `pytest`.

## Project sources

- Project purpose and links: [README.rst](README.rst)
- Contribution and Gerrit workflow: [CONTRIBUTING.rst](CONTRIBUTING.rst)
- Project-specific contributor information:
  [contributing.rst](doc/source/contributor/contributing.rst)
- Style: [HACKING.rst](HACKING.rst), [pyproject.toml](pyproject.toml), and
  [.pre-commit-config.yaml](.pre-commit-config.yaml)
- Test environments: [tox.ini](tox.ini)
- CI jobs: [.zuul.yaml](.zuul.yaml)

## Guardrails

- Do not install missing tools with a package manager or `pip`.
- This project uses Gerrit, not GitHub pull requests.
- Read-only Git operations are fine. Do not mutate Git state unless explicitly
  instructed.
