# Contributing to Role Reaper

Thank you for considering contributing to **Role Reaper**! Contributions are welcome and appreciated. This document outlines the guidelines for contributing to the project.

---

## Table of Contents

- [Contributing to Role Reaper](#contributing-to-role-reaper)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Code of Conduct](#code-of-conduct)
  - [How to Contribute](#how-to-contribute)
    - [Reporting Issues](#reporting-issues)
    - [Submitting Code Changes](#submitting-code-changes)
    - [Writing Tests](#writing-tests)
  - [Development Workflow](#development-workflow)
  - [Code Style](#code-style)
  - [Pre-Commit Hooks](#pre-commit-hooks)

---

## Getting Started

1. Fork the repository to your GitHub account.
2. Clone your forked repository:
   ```bash
   git clone https://github.com/<your-username>/role-reaper.git
   cd role-reaper
   ```
3. Install dependencies using Poetry:
   ```bash
   poetry install
   ```

---

## Code of Conduct

Please adhere to the [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming and inclusive environment for everyone.

---

## How to Contribute

### Reporting Issues

If you encounter a bug or have a feature request, please open an issue on GitHub. Provide as much detail as possible, including steps to reproduce the issue or a clear description of the feature.

### Submitting Code Changes

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```
3. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a pull request to the `main` branch of the original repository.

### Writing Tests

Ensure that your changes are covered by tests. Use `pytest` for writing and running tests:

```bash
poetry run pytest
```

---

## Development Workflow

1. **Run Tests**: Before submitting your changes, ensure all tests pass:
   ```bash
   poetry run pytest
   ```
2. **Lint Your Code**: Use `flake8`, `black`, and `isort` to ensure code quality:
   ```bash
   poetry run flake8
   poetry run black .
   poetry run isort .
   ```
3. **Run Pre-Commit Hooks**: Ensure all pre-commit hooks pass:
   ```bash
   poetry run pre-commit run --all-files
   ```

---

## Code Style

This project follows the following code style guidelines:

- **Black**: Code formatting.
- **Flake8**: Linting.
- **Isort**: Import sorting.

Configuration for these tools is already included in the repository (`pyproject.toml`, `.flake8`, `.pre-commit-config.yaml`).

---

## Pre-Commit Hooks

Pre-commit hooks are used to enforce code quality. Install them using:

```bash
poetry run pre-commit install
```

To manually run the hooks:

```bash
poetry run pre-commit run --all-files
```

---

Thank you for contributing to Role Reaper! Your efforts make this project better for everyone.
