# MCP server for PowerShell

[![PyPI](https://img.shields.io/pypi/v/mcp-server-for-powershell)](https://pypi.org/project/mcp-server-for-powershell/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/mcp-server-for-powershell?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/mcp-server-for-powershell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/danielklecha/SharpIppNext/blob/master/LICENSE.txt)

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

## Security Profiles

We recommend different configurations based on your security needs:

### Default (Balanced)
By default, the server runs in **ConstrainedLanguage** mode with a curated blocklist of dangerous commands and restricted system directories. This provides "good enough" defaults for general use, preventing common dangerous operations while allowing most read-only and safe actions.

```bash
uvx mcp-server-for-powershell
```

### Safe Mode (Strict)
For environments requiring stricter controls, use **NoLanguage** mode (`--language-mode 0`). Only built-in commands and cmdlets can be executed.

```bash
uvx mcp-server-for-powershell --language-mode 0
```

### Nuclear Mode (Allow-List Only)
For the highest security "nuclear" option, explicitly whitelist ONLY the commands you need (e.g., allow `get-items` only). This blocks **everything** else by default.

```bash
uvx mcp-server-for-powershell --allowed-commands Get-Item Get-ChildItem Get-Content
```

## License

`mcp-server-for-powershell` is provided as-is under the MIT license.
