# SPEA Lab IoT

A Python project for SPEA Lab IoT.

## Prerequisites

- [UV](https://docs.astral.sh/uv/) — fast Python package installer and resolver

Install UV (if not already installed):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or with pip:

```bash
pip install uv
```

## Managing dependencies with UV

### Create a virtual environment and install dependencies

From the project root:

```bash
uv sync
```

This creates a `.venv`, installs dependencies from `pyproject.toml`, and updates `uv.lock`.

### Add a dependency

```bash
# Production dependency
uv add <package-name>

# Development dependency (e.g. ruff)
uv add --dev <package-name>
```

Example:

```bash
uv add requests
uv add --dev ruff
```

### Remove a dependency

```bash
uv remove <package-name>
```

### Update dependencies

```bash
# Update all packages
uv lock --upgrade

# Then sync the environment
uv sync
```

### Install without modifying lock file

To install exactly what’s in `uv.lock` (e.g. in CI):

```bash
uv sync --frozen
```

### Run commands inside the virtual environment

UV can run commands using the project’s venv without activating it:

```bash
uv run python src/spea_lab_iot/main.py
uv run ruff check .
```

## Development

### Run the application

```bash
uv run python -m spea_lab_iot.main
```

Or:

```bash
uv run python src/spea_lab_iot/main.py
```

### Lint and format

```bash
uv run ruff check .
uv run ruff format .
```

## Python version

The project uses Python 3.11+ (see `.python-version`). UV will use this version when creating the environment.
