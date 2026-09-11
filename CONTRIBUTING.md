# Contributing to FalseAlarm

First off, thank you for considering contributing to FalseAlarm! It's people like you that make FalseAlarm such a great tool for the security community.

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for FalseAlarm. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

- **Use the Bug Report template** provided in the issue tracker.
- **Explain the problem** and include additional details to help maintainers reproduce the problem.
- **Include logs or output** where possible. (Ensure you redact sensitive information).

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for FalseAlarm, including completely new features and minor improvements to existing functionality.

- **Use the Feature Request template** provided in the issue tracker.
- **Provide a clear and descriptive title** for the issue to identify the suggestion.
- **Describe the current behavior** and **explain the behavior you expected to see instead** and why.

### Pull Requests

* Fill in the provided Pull Request template.
* Describe your changes in detail.
* Reference any related issues.
* Ensure all tests pass.
* Follow the styleguides below.

## Good First Issues

New to the project? These are self-contained tasks that touch one area and are
a great way to make your first contribution. Look for issues labelled
[`good first issue`](https://github.com/reikageisme/falsealarm/labels/good%20first%20issue),
or open a PR for any of these:

- **Add a YAML vulnerability template** in `falsealarm/data/templates/` for a
  specific CVE or exposed-file check (see the existing templates for the
  regex / header / negative-matcher format).
- **Add a technology signature** to `falsealarm/data/tech_signatures.json` so
  `tech` fingerprints one more CMS / framework / WAF.
- **Grow a wordlist** — extend `data/wordlists/common_dirs.txt` or
  `subdomains_top1k.txt` with high-signal, low-noise entries.
- **Improve the Markdown handoff report** (`core/report.py`) — clearer
  severity grouping or a findings summary table.
- **Add tests** for an under-covered module in `tests/`.
- **Docs** — add a real-world workflow to [`docs/USAGE.md`](docs/USAGE.md).

Small, focused PRs get reviewed fastest. When in doubt, open an issue first to
discuss the approach.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Consider using Conventional Commits formats (e.g., `feat:`, `fix:`, `docs:`, `refactor:`)

### Python Styleguide

* All Python must adhere to [PEP 8](https://www.python.org/dev/peps/pep-0008/).
* Use `flake8` or `black` for formatting.
* Provide type hints (PEP 484) for all new functions and methods.
* Write docstrings for all modules, classes, and public functions using Google Style.

## Local Development Setup

1. Fork the repo and create your branch from `main`.
2. Install dependencies: `pip install -e .`
3. If you've added code that should be tested, add tests.
4. If you've changed APIs, update the documentation.
5. Ensure the test suite passes.

Thank you for contributing!
