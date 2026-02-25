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

## Environment variables

Scripts load variables from a `.env` file (copy `example.env` to `.env` and adjust). Each entry-point script calls `load_dotenv()` at startup so values are available before config is read.

| Variable | Used by | Description |
|----------|---------|-------------|
| `MQTT_BROKER_HOST` | All | Broker host (default: `public.cloud.shiftr.io`) |
| `MQTT_BROKER_PORT` | All | Broker port (default: `1883`) |
| `MQTT_USER` | All | MQTT username (default: `public`) |
| `MQTT_PASSWORD` | All | MQTT password (default: `public`) |
| `PLATFORM_DEFAULT_PIN` | Platform | Default PIN for keypad devices; key `"default"` cannot be removed |
| `PLATFORM_LOG` | Platform | Set to `1` or `true` to enable log mode on startup |
| `KEY_ROTATION_INTERVAL_SEC` | Device / Platform | Seconds between automatic session key rotations (default: `60`) |
| `KEY_ROTATION_MSG_LIMIT` | Device / Platform | Number of messages before triggering key rotation (default: `100`) |

## Python version

The project uses Python 3.11+ (see `.python-version`). UV will use this version when creating the environment.

## Docs

- **MQTT demo** (sensor + subscriber, no enrollment): [docs/MQTT_DEMO.md](docs/MQTT_DEMO.md)
- **R1: Enrollable devices + platform** (pairing, keypad/screen, iot/feed): [docs/R1_DEVICE_PLATFORM.md](docs/R1_DEVICE_PLATFORM.md)
- **R2: Key Management** (Master Key, Session Key, rotation): [docs/R2_KEY_MANAGEMENT.md](docs/R2_KEY_MANAGEMENT.md)
- **R5: Data Encryption** (AES-GCM, AES-CBC+HMAC): [docs/R5_DATA_ENCRYPTION.md](docs/R5_DATA_ENCRYPTION.md)
