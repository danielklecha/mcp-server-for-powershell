# MCP server for PowerShell

[![PyPI](https://img.shields.io/pypi/v/mcp-server-for-powershell)](https://pypi.org/project/mcp-server-for-powershell/)

## Disclaimer

**Unofficial Implementation**: This project is an independent open-source software project. It is **not** affiliated with, endorsed by, sponsored by, or associated with **Microsoft Corporation** or the **PowerShell** team.

**Trademarks**: "PowerShell" and the PowerShell logo are trademarks or registered trademarks of Microsoft Corporation in the United States and/or other countries. All other trademarks cited herein are the property of their respective owners. Use of these names is for descriptive purposes only (nominative fair use) to indicate compatibility.

## Installation

* **Run directly with [uv](https://docs.astral.sh/uv/) (recommended)**: `uvx mcp-server-for-powershell`
* **pip**: `pip install mcp-server-for-powershell`
* **uv**: `uv pip install mcp-server-for-powershell`

## Configuration

The server can be configured using the following command-line arguments:

| Argument                   | Description                                                                                                          | Default            |
| :------------------------- | :------------------------------------------------------------------------------------------------------------------- | :----------------- |
| `--allowed-commands`       | List of allowed PowerShell commands. If empty, all are allowed (subject to restrictions).                            | `[]`               |
| `--restricted-commands`    | List of restricted PowerShell commands.                                                                              | Safe defaults      |
| `--restricted-directories` | List of restricted directories.                                                                                      | System directories |
| `--language-mode`          | PowerShell Language Mode: `0` (NoLanguage), `1` (ConstrainedLanguage), `2` (RestrictedLanguage), `3` (FullLanguage). | `1`                |
| `--cwd`                    | Initial working directory.                                                                                           | Current Directory  |

### Language Modes

- **0 (NoLanguage)**: No script execution allowed.
- **1 (ConstrainedLanguage)**: Restricts access to sensitive language elements (default).
- **2 (RestrictedLanguage)**: Only allows basic commands.
- **3 (FullLanguage)**: Unrestricted access.

## License

`mcp-server-for-powershell` is provided as-is under the MIT license.
