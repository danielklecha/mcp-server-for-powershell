import argparse
import base64
import logging
import os
import pathlib
import re
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

# Global configuration
ALLOWED_COMMANDS = []
RESTRICTED_COMMANDS = None
RESTRICTED_DIRECTORIES = None
LANGUAGE_MODE = 1
SERVER_CWD = None

# Standard logger for auditing blocked/invalid operations
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _get_default_restricted_commands() -> list[str]:
    """Returns a list of default restricted commands based on the operating system."""

    # Cross-platform Critical Restrictions
    common_commands = [
        # Execution/Process
        "Invoke-Expression",
        "iex",
        "Start-Process",
        "start",
        "spps",
        "Stop-Process",
        "kill",
        "spp",
        "Restart-Computer",
        "Stop-Computer",
        ".",  # Dot-sourcing
        "Add-Type",  # Compilation
        # Session / Navigation
        "Enter-PSSession",
        "New-PSSession",
        "Set-Location",
        "cd",
        "chdir",
        "sl",
        "Push-Location",
        "pushd",
        "Pop-Location",
        "popd",
        # Dangerous / System
        "&",
        "call",  # Call operator
        "Out-File",
        "tee",
        "Tee-Object",
        "Set-Item",
        "si",
        "Clear-Item",
        "cli",
        "Invoke-Item",
        "ii",
        "New-Alias",
        "nal",
        "Set-Alias",
        "sal",
        "Invoke-Command",
        "icm",
        # Objects (DotNet/COM - New-Object is cross-platform)
        "New-Object",
        # Process/Shell escapism
        "pwsh",
        "powershell",
        # Privacy / Secrets
        "Get-Clipboard",
        "gcb",
        "Set-Clipboard",
        "scb",
        "Get-Variable",
        "gv",
        # File System (Modifications usually restricted by default)
        "Remove-Item",
        "rm",
        "rd",
        "erase",
        "del",
        "ri",
        "New-Item",
        "ni",
        "md",
        "mkdir",
        "Set-Content",
        "sc",
        "Add-Content",
        "ac",
        "Clear-Content",
        "clc",
        "Copy-Item",
        "cp",
        "copy",
        "cpi",
        "Move-Item",
        "mv",
        "move",
        "mi",
        "Rename-Item",
        "ren",
        "rni",
        # Drive Management
        "New-PSDrive",
        "Remove-PSDrive",
        # Module Management
        "Install-Module",
        "Uninstall-Module",
        "Update-Module",
        "Save-Module",
        "Publish-Module",
        "Import-Module",
        "Remove-Module",
        "Add-PSSnapin",
        "Remove-PSSnapin",
        "Install-Script",
        "Save-Script",
        "Uninstall-Script",
        "Install-Package",
        "Uninstall-Package",
        "Install-PackageProvider",
        "Save-Package",
        "Find-Package",
        "Find-PackageProvider",
        "Get-PackageProvider",
        "Uninstall-PackageProvider",
        "Get-Package",
        "Get-PackageSource",
        "Register-PackageSource",
        "Unregister-PackageSource",
        "Get-PackageSource",
        # PowerShell repository
        "Register-PSRepository",
        "Register-PSResourceRepository",
        "Set-PSRepository",
        # Job Management
        "Start-Job",
        "sajb",
        "Stop-Job",
        "spjb",
        "Remove-Job",
        "rjb",
        # Debugging
        "Debug-Process",
        "Debug-Job",
        # WMI / CIM Management (OMI can enable these on Linux)
        "Invoke-CimMethod",
        "Invoke-WmiMethod",
        "Set-WmiInstance",
        "Set-CimInstance",
        "New-CimInstance",
        "New-WmiObject",
        "Remove-CimInstance",
        "Remove-WmiObject",
        "Register-CimIndicationEvent",
        "Register-WmiEvent",
        # File Export / Writing
        "Export-Csv",
        "Export-Clixml",
        "Export-Html",
        "Export-Json",
        "Export-Alias",
        "Export-Console",
        "Export-Counter",
        # Archive Management (Read/Write)
        "Compress-Archive",
        "Expand-Archive",
        # Background Intelligent Transfer Service (can transfer files silently)
        "Start-BitsTransfer",
        # Transcript (Writes to disk)
        "Start-Transcript",
        "Stop-Transcript",
        # Variable Management (State Modification)
        "New-Variable",
        "nv",
        "Set-Variable",
        "sb",
        "sv",
        "Remove-Variable",
        "rv",
        "Clear-Variable",
        "clv",
        # Session / Management extended
        "Connect-PSSession",
        "Disconnect-PSSession",
        "Receive-PSSession",
        "Enter-PSHostProcess",
        "Exit-PSHostProcess",
        # UI / Printers
        "Show-Command",
        "Out-Printer",
        "lp",
        # Interactive
        "Read-Host",
        "Get-Credential",
        "Out-GridView",
        "Out-ConsoleGridView",
    ]

    # Windows-specific Restrictions
    if os.name == "nt":
        common_commands.extend(
            [
                # Analysis Services
                "Invoke-ASCmd",
                # System / Management
                "Set-ExecutionPolicy",
                "Clear-EventLog",
                "Limit-EventLog",
                "Remove-EventLog",
                "New-EventLog",
                "Write-EventLog",
                # Process/Shell escapism (Windows binaries)
                "cmd",
                "cmd.exe",
                "wscript",
                "cscript",
                "powershell.exe",
                "pwsh.exe",
                "bash.exe",
                "wsl.exe",
                # Service Management
                "Start-Service",
                "sasv",
                "Stop-Service",
                "spsv",
                "Restart-Service",
                "Suspend-Service",
                "ssv",
                "Resume-Service",
                "Set-Service",
                "New-Service",
                "Remove-Service",
                # System Configuration
                "Add-Computer",
                "Remove-Computer",
                "Rename-Computer",
                "Join-Domain",
                "Checkpoint-Computer",
                "Restore-Computer",
                # Remoting / WSMan
                "Enable-PSRemoting",
                "Disable-PSRemoting",
                "Enable-WSManCredSSP",
                "Disable-WSManCredSSP",
                # Disk / Volume Management
                "Format-Volume",
                "Clear-Disk",
                "Resize-Partition",
                "Remove-Partition",
                "Optimize-Volume",
                # Security / System Modification
                "Set-Acl",
                "Unblock-File",
                "Set-Date",
                # Registry Property Management
                "Set-ItemProperty",
                "sp",
                "New-ItemProperty",
                "Remove-ItemProperty",
                "Rename-ItemProperty",
                "Copy-ItemProperty",
                "Move-ItemProperty",
                "Clear-ItemProperty",
                "clp",
                # Local User/Group Management
                "New-LocalUser",
                "Set-LocalUser",
                "Remove-LocalUser",
                "Enable-LocalUser",
                "Disable-LocalUser",
                "Rename-LocalUser",
                "New-LocalGroup",
                "Remove-LocalGroup",
                "Rename-LocalGroup",
                "Add-LocalGroupMember",
                "Remove-LocalGroupMember",
                # Defender / Firewall / Security
                "Set-MpPreference",
                "Add-MpPreference",
                "Remove-MpPreference",
                "Set-NetFirewallRule",
                "New-NetFirewallRule",
                "Remove-NetFirewallRule",
                # Scheduled Tasks
                "Register-ScheduledTask",
                "Unregister-ScheduledTask",
                "Set-ScheduledTask",
                # Certificates
                "Export-PfxCertificate",
                "Export-Certificate",
                # Native Windows Binaries
                "reg.exe",
                "reg",
                "net.exe",
                "net",
                "netsh.exe",
                "netsh",
                "schtasks.exe",
                "schtasks",
                "attrib.exe",
                "attrib",
                "icacls.exe",
                "icacls",
                "takeown.exe",
                "takeown",
                "vssadmin.exe",
                "vssadmin",
                "taskkill.exe",
                "taskkill",
                "sc.exe",
                "shutdown.exe",
                "shutdown",
                "wmic.exe",
                "wmic",
                "rundll32.exe",
                "rundll32",
                "mshta.exe",
                "mshta",
                "regsvr32.exe",
                "regsvr32",
                "certutil.exe",
                "certutil",
                "bitsadmin.exe",
                "bitsadmin",
                "msiexec.exe",
                "msiexec",
                "ftp.exe",
                "ftp",
                "tftp.exe",
                "tftp",
                "curl.exe",
                "wget.exe",
                # LOLBins
                "MSBuild.exe",
                "InstallUtil.exe",
                "PresentationHost.exe",
                "diskshadow.exe",
                "odbcconf.exe",
                "forfiles.exe",
                "pcalua.exe",
                "tracker.exe",
                "regasm.exe",
                "regsvcs.exe",
            ]
        )

    return common_commands


DEFAULT_RESTRICTED_COMMANDS = _get_default_restricted_commands()


def _get_default_restricted_directories() -> list[str]:
    """Returns a list of default restricted directories based on the operating system."""
    # Cross-platform PowerShell Drives
    common_defaults = ["Env:", "Variable:", "Alias:", "Function:"]

    if os.name == "nt":
        return common_defaults + [
            # Windows-specific Drives
            "HKLM:",
            "HKCU:",
            "Cert:",
            "WSMan:",
            # System Directories
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
        ]
    else:
        # Linux / POSIX defaults
        return common_defaults + [
            "/etc",
            "/root",
        ]


DEFAULT_RESTRICTED_DIRECTORIES = _get_default_restricted_directories()

# Initialize the MCP server
mcp = FastMCP("powershell-integration")


def _is_restricted_path(path_input: str | pathlib.Path, cwd_path: pathlib.Path) -> bool:
    """
    Checks if the path is in a restricted directory.
    Resolves relative paths against the provided cwd_path.
    Returns True if restricted, False otherwise.
    """
    dirs_to_check = list(
        RESTRICTED_DIRECTORIES if RESTRICTED_DIRECTORIES is not None else DEFAULT_RESTRICTED_DIRECTORIES
    )

    # 0. Pre-check for special drive syntax (e.g. HKLM:, Env:)
    # We check if the input string starts with any of the restricted paths that look like drives.
    # This prevents bypassing normalization, as pathlib might not handle 'Env:' correctly on all OSes or might not see it as absolute.
    str_input = str(path_input)
    # Normalize slashes for comparison just in case, though drives usually don't have them at start
    str_input_norm = str_input.replace("/", "\\")

    for d in dirs_to_check:
        if d.endswith(":"):  # It's a drive-like restriction
            # Check if input starts with this drive (case-insensitive)
            if str_input_norm.lower().startswith(d.lower()):
                return True

    # 1. Resolve the target path
    path_obj = None
    try:
        if isinstance(path_input, pathlib.Path):
            p = path_input
        else:
            p = pathlib.Path(path_input)

        # If absolute, use as is. If relative, join with cwd.
        if p.is_absolute():
            path_obj = p
        else:
            path_obj = cwd_path.joinpath(p)

        # Normalize (resolve symlinks/dots if possible, otherwise absolute)
        # We use os.path.abspath to resolve .. and symlinks effectively on Windows/Posix
        path_obj = pathlib.Path(os.path.abspath(str(path_obj)))

    except Exception:
        # unexpected error (e.g. null bytes)
        pass

    if path_obj:
        # Check against restricted directories using normalized absolute paths to avoid bypasses
        path_str = os.path.normcase(os.path.abspath(str(path_obj)))
        for d in dirs_to_check:
            if d.endswith(":"):
                continue
            try:
                r_str = os.path.normcase(os.path.abspath(str(d)))
                # Match exact path or ancestor (ensure separator so '/etc' doesn't match '/etc2')
                if path_str == r_str or path_str.startswith(r_str + os.sep):
                    return True
            except Exception:
                pass
    return False


def _log_and_raise(msg: str):
    """Helper to log a warning and raise ValueError with the same message."""
    logger.warning(msg)
    raise ValueError(msg)


def _validate_parameter(value: str, cwd_path: pathlib.Path) -> None:
    """Validates if a string parameter resolves to a restricted directory."""
    if not isinstance(value, str):
        return
    # Validating parameter with awareness of CWD
    if _is_restricted_path(value, cwd_path):
        _log_and_raise(f"Access to restricted directory path '{value}' is denied.")


def _serialize_parameter(value, cwd_path: pathlib.Path) -> str:
    """Serializes a Python value to a PowerShell literal string."""
    # Always validate the parameter first
    _validate_parameter(value, cwd_path)

    if isinstance(value, bool):
        return "$true" if value else "$false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        # Escape single quotes and wrap in single quotes
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    elif isinstance(value, list):
        # PowerShell array @(v1, v2)
        items = [_serialize_parameter(v, cwd_path) for v in value]
        return "@(" + ", ".join(items) + ")"
    elif isinstance(value, dict):
        # PowerShell hashtable @{k=v; ...}
        items = [f"{k} = {_serialize_parameter(v, cwd_path)}" for k, v in value.items()]
        return "@{" + "; ".join(items) + "}"
    elif value is None:
        return "$null"
    else:
        # Fallback to string representation
        return _serialize_parameter(str(value), cwd_path)


def _validate_command(cmd_name: str, cwd_path: pathlib.Path) -> None:
    """Validates if the command is in the allowed list."""
    if not cmd_name:
        _log_and_raise("Invalid command object: missing 'command' field.")

    # Check for whitespace in command name (prevent injection/obfuscation)
    # Checks for space, tab, newline, etc.
    if re.search(r"\s", cmd_name):
        _log_and_raise(f"Command name '{cmd_name}' contains whitespace (space, tab, etc.), which is not allowed.")

    # Canonicalize the command for robust comparisons (basename + lower-case)
    # Strip quotes and whitespace
    cmd_clean = cmd_name.strip().strip("'\"")

    # Prepare comparison key for Restricted Lists
    # We use basename to prevent path-based bypass (e.g. .\certutil.exe vs certutil.exe)
    # .NET methods ([Console]::WriteLine) pass through basename unchanged.
    try:
        comparison_key = os.path.basename(cmd_clean).lower()
    except Exception:
        comparison_key = cmd_clean.lower()

    cmds_to_check = RESTRICTED_COMMANDS if RESTRICTED_COMMANDS is not None else DEFAULT_RESTRICTED_COMMANDS

    # 1. Check Allow List (Priority)
    if ALLOWED_COMMANDS:
        if comparison_key in [ac.lower() for ac in ALLOWED_COMMANDS]:
            return  # Explicitly allowed

        # If Allow List is active but command is not in it, deny.
        _log_and_raise(f"Command '{cmd_name}' is not in the allowed list.")

    # Check Restricted Directory BEFORE getting basename (so we check full path)
    if any(sep in cmd_clean for sep in [os.sep, "/", "\\"]):
        if _is_restricted_path(cmd_clean, cwd_path):
            _log_and_raise(f"Command path '{cmd_clean}' is in a restricted directory.")

    # 2. Check Restricted List (Default fallback)
    if comparison_key in [rc.lower() for rc in cmds_to_check]:
        _log_and_raise(f"Command '{cmd_name}' is restricted and cannot be executed.")


def _build_dotnet_command(cmd_name: str, params: list | None, cwd_path: pathlib.Path) -> str:
    """Builds a .NET static method call string."""
    if params:
        if isinstance(params, list):
            # Serialize each arg
            args_str = ", ".join([_serialize_parameter(p, cwd_path) for p in params])
            return f"{cmd_name}({args_str})"
        else:
            # Treat as single parameter
            return f"{cmd_name}({_serialize_parameter(params, cwd_path)})"
    else:
        # invocations without args
        return f"{cmd_name}()"


def _build_standard_command(cmd_name: str, params: list | dict | None, cwd_path: pathlib.Path) -> str:
    """Builds a standard PowerShell cmdlet string."""
    parts = [cmd_name]
    if params:
        if isinstance(params, list):
            # Positional args or distinct flags
            for p in params:
                parts.append(_serialize_parameter(p, cwd_path))
        elif isinstance(params, dict):
            # Named parameters
            for k, v in params.items():
                # Parameter names must be strings. If they don't start with '-', auto-prefix it.
                if not isinstance(k, str):
                    _log_and_raise(
                        f"Parameter name '{k}' for command '{cmd_name}' must be a string and start with '-'."
                    )
                if not k.startswith("-"):
                    k = f"-{k}"
                parts.append(k)
                parts.append(_serialize_parameter(v, cwd_path))
        else:
            raise ValueError(f"Parameters must be a list or dict, got {type(params)}")
    return " ".join(parts)


def _build_command_chain(cmd_obj: dict, cwd_path: pathlib.Path) -> str:
    """
    Recursively builds a command string from a command object.
    Handles 'command', 'parameters', and 'then' (pipeline).
    """
    cmd_name = cmd_obj.get("command")
    _validate_command(cmd_name, cwd_path)

    params = cmd_obj.get("parameters")

    # Check if this is a .NET static method call: [Class]::Method
    # Heuristic: Starts with [, contains ]::
    is_dotnet_method = bool(re.match(r"^\[.+\]::.+$", cmd_name))

    if is_dotnet_method:
        current_cmd = _build_dotnet_command(cmd_name, params, cwd_path)
    else:
        current_cmd = _build_standard_command(cmd_name, params, cwd_path)

    # Handle pipeline
    next_cmd_obj = cmd_obj.get("then")
    if next_cmd_obj:
        return f"{current_cmd} | {_build_command_chain(next_cmd_obj, cwd_path)}"

    return current_cmd


def _construct_script(json_input: list | dict, cwd_path: pathlib.Path) -> str:
    """
    Parses the JSON input and constructs the full PowerShell script.
    Input can be a single command object or a list of command objects (sequential).
    """
    if isinstance(json_input, dict):
        json_input = [json_input]

    if not isinstance(json_input, list):
        raise ValueError("Input must be a JSON object or array.")

    statements = []
    for cmd in json_input:
        statements.append(_build_command_chain(cmd, cwd_path))

    # Join sequential commands with semicolon
    return "; ".join(statements)


def _fix_json_escapes(json_str: str) -> str:
    """
    Attempts to fix common JSON escaping issues, specifically unescaped backslashes
    in strings (e.g. 'C:\\Windows' -> 'C:\\\\Windows').
    """
    # Pattern matches:
    # Group 1: Valid escape sequences (e.g. \n, \\, \", \uXXXX)
    # Group 2: Invalid backslash (not followed by a valid escape char)
    # Valid escapes in JSON: " \ / b f n r t u
    pattern = r'(\\[\\"/bfnrtu])|(\\)'

    def replace_match(match):
        # If it's a valid escape (Group 1), keep it
        if match.group(1):
            return match.group(1)
        # If it's an invalid backslash (Group 2), escape it
        return "\\\\"

    return re.sub(pattern, replace_match, json_str)


# Define the command to run PowerShell code
@mcp.tool()
def run_powershell(json: str) -> str:
    """
    Executes PowerShell commands based on a structured JSON definition.

    This tool allows you to run PowerShell commands safely strings.
    It expects a JSON string that defines the command(s), parameters, pipelines, and sequences.

    Args:
        json: A JSON string defining the command structure.
              Structure examples:
              1. Single Command:
                 [{"command": "Get-Item", "parameters": ["."]}]

              2. .NET Static Method:
                 [{"command": "[System.Math]::Sqrt", "parameters": [16]}]
                 # Generates: [System.Math]::Sqrt(16)

              3. Command with Named Parameters:
                 [{"command": "Get-Item", "parameters": {"-Path": "."}}]

              4. Pipeline:
                 [{"command": "Get-Process", "then": {"command": "Select-Object", "parameters": ["Name"]}}]

              5. Sequence (Multiple commands):
                 [{"command": "mkdir", "parameters": ["test"]}, {"command": "cd", "parameters": ["test"]}]

    Returns:
        The standard output of the executed PowerShell command(s), or an error message if execution fails.
    """
    # Use global SERVER_CWD if set, otherwise current working directory
    cwd = SERVER_CWD if SERVER_CWD else os.getcwd()
    cwd = os.path.abspath(cwd)

    # Check restricted directories
    cwd_path = pathlib.Path(cwd)
    try:
        # Validate effective CWD
        # Using the same CWD validation logic
        if _is_restricted_path(cwd_path, cwd_path):
            raise ValueError(f"Access to restricted directory '{cwd}' is denied.")

    except ValueError as ve:
        return f"Error: Execution halted. {ve}"
    except Exception as e:
        return f"Error checking restricted directories: {e}"

    # 1. Parse JSON
    try:
        import json as json_module

        data = json_module.loads(json)
    except Exception as e:
        try:
            # Try to fix unescaped backslashes
            fixed_json = _fix_json_escapes(json)
            data = json_module.loads(fixed_json)
        except Exception:
            return f"Error parsing JSON input: {e!s}"

    # 2. Construct Script
    try:
        script_text = _construct_script(data, cwd_path)
    except ValueError as e:
        return f"Error constructing command: {e!s}"

    # 3. Prepare for execution
    # Prepend Language Mode configuration
    mode_map = {0: "NoLanguage", 1: "ConstrainedLanguage", 2: "RestrictedLanguage", 3: "FullLanguage"}

    language_mode_str = mode_map.get(LANGUAGE_MODE, "RestrictedLanguage")

    if language_mode_str != "FullLanguage":
        script_text = (
            f'if ($null -ne $PSStyle) {{ $PSStyle.OutputRendering = "PlainText" }}; $ExecutionContext.SessionState.LanguageMode = "{language_mode_str}"; '
            + script_text
        )
    else:
        script_text = 'if ($null -ne $PSStyle) { $PSStyle.OutputRendering = "PlainText" }; ' + script_text

    # 4. Execute using pwsh
    # Strategy:
    # - If mode is NoLanguage (0) or RestrictedLanguage (2): use -Command with escaped quotes to avoid exit code 1 issues.
    # - Otherwise: use -EncodedCommand for robustness.

    cmd_args = [
        "pwsh",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Restricted",
        "-InputFormat",
        "Text",
        "-OutputFormat",
        "Text",
    ]

    try:
        if LANGUAGE_MODE in [0, 2]:
            # Use -Command with escaped quotes
            # Escape double quotes for Windows argument parsing if needed, but primarily for pwsh -Command
            # We replace " with \" to ensure they are preserving within the command string
            script_escaped = script_text.replace('"', '\\"')
            cmd_args.extend(["-Command", script_escaped])
        else:
            # Use UTF-16LE for PowerShell 'EncodedCommand'
            encoded_command = base64.b64encode(script_text.encode("utf-16le")).decode("ascii")
            cmd_args.extend(["-EncodedCommand", encoded_command])

        process = subprocess.Popen(
            cmd_args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        output, error = process.communicate()

        if process.returncode != 0:
            return f"Error (Exit Code {process.returncode}): {error}"

        return output
    except FileNotFoundError:
        return "Error: 'pwsh' not found. Please ensure PowerShell 7+ is installed and in PATH."
    except Exception as e:
        return f"Error executing command: {e!s}"


def main():
    global ALLOWED_COMMANDS, RESTRICTED_COMMANDS, RESTRICTED_DIRECTORIES, LANGUAGE_MODE, SERVER_CWD

    parser = argparse.ArgumentParser(description="PowerShell MCP Server")
    parser.add_argument(
        "--allowed-commands",
        nargs="*",
        help="List of allowed PowerShell commands (if empty, all are allowed)",
        default=[],
    )

    parser.add_argument(
        "--restricted-commands",
        nargs="*",
        help="List of restricted PowerShell commands. If not provided, defaults to a safe set of restrictions.",
        default=None,
    )

    parser.add_argument(
        "--restricted-directories",
        nargs="*",
        help="List of restricted directories. If not provided, defaults to system directories.",
        default=None,
    )

    parser.add_argument(
        "--language-mode",
        type=int,
        choices=[0, 1, 2, 3],
        help="Set PowerShell Language Mode: 0=NoLanguage, 1=ConstrainedLanguage (default), 2=RestrictedLanguage, 3=FullLanguage",
        default=1,
    )

    parser.add_argument("--cwd", help="Set the initial working directory for the server.", default=None)

    args, unknown = parser.parse_known_args()

    if args.allowed_commands:
        ALLOWED_COMMANDS = args.allowed_commands
        # print(f"Server starting with allowed commands: {ALLOWED_COMMANDS}", file=sys.stderr)

    if args.restricted_commands is not None:
        # If user explicitly provided restricted commands, we respect that list exactly.
        # This implies user has full control to add or remove restrictions.
        RESTRICTED_COMMANDS = args.restricted_commands
    else:
        # Default behavior: All default restrictions apply
        RESTRICTED_COMMANDS = DEFAULT_RESTRICTED_COMMANDS

    if args.restricted_directories is not None:
        RESTRICTED_DIRECTORIES = args.restricted_directories
    else:
        RESTRICTED_DIRECTORIES = DEFAULT_RESTRICTED_DIRECTORIES

    if args.language_mode is not None:
        LANGUAGE_MODE = args.language_mode

    if args.cwd:
        # Resolve to absolute path
        resolved_cwd = os.path.abspath(args.cwd)

        # Validate against restricted directories
        # We use current process CWD as base for _is_restricted_path, though resolved_cwd is absolute.
        if _is_restricted_path(resolved_cwd, pathlib.Path(os.getcwd())):
            print(f"Error: The specified working directory '{resolved_cwd}' is restricted.", file=sys.stderr)
            sys.exit(1)

        SERVER_CWD = resolved_cwd

    # Run the MCP server
    mcp.run()


if __name__ == "__main__":
    main()
