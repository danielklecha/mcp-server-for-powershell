# Contributing

## Development

- `uv sync`: Create virtual environment and install dependencies.
- `uv run mcp-server-for-powershell`: Run the server.
- `uv build`: Build the package.

## Testing

To run the tests, use the following command:

```bash
uv run pytest
```

### Coverage

To run tests with coverage reporting:

```bash
uv run pytest --cov=mcp_server_for_powershell
```

## Code Style

This project uses `ruff` for code style.

```bash
uv run ruff check .
uv run ruff format --check .
```

To automatically fix standard style issues:

```bash
uv run ruff format .
uv run ruff check --fix .
```
