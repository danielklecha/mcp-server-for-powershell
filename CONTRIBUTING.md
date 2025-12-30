# Contributing

## Development

- `hatch env create`: Create virtual environment.
- `hatch shell`: Enter the environment.
- `hatch run mcp-server-for-powershell`: Run the server.
- `hatch build`: Build the package.
- `hatch clean`: Clean up the environment.
- `hatch run cov`: Run tests with coverage reporting.

## Testing

To run the tests, use the following command:

```bash
hatch test
```

### Coverage

To run tests with coverage reporting:

```bash
hatch run cov
```

## Code Style

This project uses `ruff` and `black` for code style.

```bash
hatch run lint:style
```

To automatically fix standard style issues:

```bash
hatch run lint:fmt
```
