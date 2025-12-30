import argparse
import shlex
import re
import sys
import os
import json
from mcp.server.fastmcp import FastMCP
import base64
import subprocess
import pathlib

# Global configuration
ALLOWED_COMMANDS = []
RESTRICTED_COMMANDS = []
RESTRICTED_DIRECTORIES = []
RESTRICTED_DIRECTORIES = []
LANGUAGE_MODE = 1
SERVER_CWD = None

OPTIONAL_RESTRICTED_COMMANDS = [
    # File System
    "Remove-Item", "rm", "rd", "erase", "del", "ri",
    "New-Item", "ni", "md", "mkdir",
    "Set-Content", "sc", 
    "Add-Content", "ac",
    "Clear-Content", "clc",
    "Copy-Item", "cp", "copy", "cpi",
    "Move-Item", "mv", "move", "mi",
    "Rename-Item", "ren", "rni",
]

REQUIRED_RESTRICTED_COMMANDS = [
    # Execution/Process
    "Invoke-Expression", "iex",
    "Start-Process", "start", "spps",
    "Stop-Process", "kill", "spp",
    "Restart-Computer",
    "Stop-Computer",

    # Sessions
    "Enter-PSSession",
    "New-PSSession",

    # Objects
    "New-Object",

    # Navigation
    "Set-Location", "cd", "chdir", "sl",
    "Push-Location", "pushd",
    "Pop-Location", "popd",

    # Dangerous / System
    "&", "call", # Call operator
    "Out-File", "tee", "Tee-Object",
    "Set-Item", "si",
    "Clear-Item", "cli",
    "Invoke-Item", "ii",
    "New-Alias", "nal", "Set-Alias", "sal",
    "Invoke-Command", "icm",
    
    # Process/Shell escapism
    "pwsh", "powershell", "cmd", "cmd.exe", "wscript", "cscript"
]

DEFAULT_RESTRICTED_COMMANDS = REQUIRED_RESTRICTED_COMMANDS + OPTIONAL_RESTRICTED_COMMANDS

DEFAULT_RESTRICTED_DIRECTORIES = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
]

# Initialize the MCP server
mcp = FastMCP("powershell-integration")

def _is_restricted_path(path_input: str | pathlib.Path, cwd_path: pathlib.Path) -> bool:
    """
    Checks if the path is in a restricted directory.
    Resolves relative paths against the provided cwd_path.
    Returns True if restricted, False otherwise.
    """
    dirs_to_check = list(RESTRICTED_DIRECTORIES if RESTRICTED_DIRECTORIES else DEFAULT_RESTRICTED_DIRECTORIES)
    
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
        # Check against restricted directories
        for d in dirs_to_check:
            r_path = pathlib.Path(d)
            try:
                # We need to ensure r_path is absolute for comparison
                if not r_path.is_absolute():
                     r_path = r_path.absolute()
                
                # Check match or ancestry
                if path_obj == r_path or r_path in path_obj.parents:
                     return True
            except Exception:
                pass
    return False

def _validate_parameter(value: str, cwd_path: pathlib.Path) -> None:
    """Validates if a string parameter resolves to a restricted directory."""
    if not isinstance(value, str):
        return
    # Validating parameter with awareness of CWD
    if _is_restricted_path(value, cwd_path):
         raise ValueError(f"Access to restricted directory path '{value}' is denied.")

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

def _validate_command(cmd_name: str) -> None:
    """Validates if the command is in the allowed list."""
    if not cmd_name:
        raise ValueError("Invalid command object: missing 'command' field.")
    
    # Check for whitespace in command name (prevent injection/obfuscation)
    # Checks for space, tab, newline, etc.
    if re.search(r'\s', cmd_name):
        raise ValueError(f"Command name '{cmd_name}' contains whitespace (space, tab, etc.), which is not allowed.")
        
    cmds_to_check = RESTRICTED_COMMANDS if RESTRICTED_COMMANDS else DEFAULT_RESTRICTED_COMMANDS
    
    if cmd_name.lower() in [rc.lower() for rc in cmds_to_check]:
        raise ValueError(f"Command '{cmd_name}' is restricted and cannot be executed.")

    if ALLOWED_COMMANDS:
        # Note: A .NET method call usually won't match a simple allowlist unless the list contains the full method or class
        # For now, we assume if ALLOWED_COMMANDS is set, we check against it.
        if cmd_name.lower() not in [ac.lower() for ac in ALLOWED_COMMANDS]:
             raise ValueError(f"Command '{cmd_name}' is not in the allowed list.")

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
    _validate_command(cmd_name)

    params = cmd_obj.get("parameters")
    
    # Check if this is a .NET static method call: [Class]::Method
    # Heuristic: Starts with [, contains ]::
    is_dotnet_method = bool(re.match(r'^\[.+\]::.+$', cmd_name))

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
             return f"Error parsing JSON input: {str(e)}"
    
    # 2. Construct Script
    try:
        script_text = _construct_script(data, cwd_path)
    except ValueError as e:
        return f"Error constructing command: {str(e)}"

    # 3. Prepare for execution
    # Prepend Language Mode configuration
    mode_map = {
        0: "NoLanguage",
        1: "ConstrainedLanguage",
        2: "RestrictedLanguage",
        3: "FullLanguage"
    }
    
    language_mode_str = mode_map.get(LANGUAGE_MODE, "RestrictedLanguage")
    
    if language_mode_str != "FullLanguage":
         script_text = f'if ($null -ne $PSStyle) {{ $PSStyle.OutputRendering = "PlainText" }}; $ExecutionContext.SessionState.LanguageMode = "{language_mode_str}"; ' + script_text
    else:
         script_text = f'if ($null -ne $PSStyle) {{ $PSStyle.OutputRendering = "PlainText" }}; ' + script_text

    # 4. Execute using pwsh
    # Strategy:
    # - If mode is NoLanguage (0) or RestrictedLanguage (2): use -Command with escaped quotes to avoid exit code 1 issues.
    # - Otherwise: use -EncodedCommand for robustness.
    
    cmd_args = [
        "pwsh",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Restricted",
        "-InputFormat", "Text",
        "-OutputFormat", "Text"
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
        return f"Error executing command: {str(e)}"


def main():
    global ALLOWED_COMMANDS, RESTRICTED_COMMANDS, RESTRICTED_DIRECTORIES, LANGUAGE_MODE, SERVER_CWD

    parser = argparse.ArgumentParser(description="PowerShell MCP Server")
    parser.add_argument(
        "--allowed-commands",
        nargs="*",
        help="List of allowed PowerShell commands (if empty, all are allowed)",
        default=[]
    )
    
    parser.add_argument(
        "--restricted-commands",
        nargs="*",
        help="List of restricted PowerShell commands. If not provided, defaults to a safe set of restrictions.",
        default=None
    )

    parser.add_argument(
        "--restricted-directories",
        nargs="*",
        help="List of restricted directories. If not provided, defaults to system directories.",
        default=None
    )

    parser.add_argument(
        "--language-mode",
        type=int,
        choices=[0, 1, 2, 3],
        help="Set PowerShell Language Mode: 0=NoLanguage, 1=ConstrainedLanguage (default), 2=RestrictedLanguage, 3=FullLanguage",
        default=1
    )

    parser.add_argument(
        "--cwd",
        help="Set the initial working directory for the server.",
        default=None
    )
    
    args, unknown = parser.parse_known_args()
    
    if args.allowed_commands:
        ALLOWED_COMMANDS = args.allowed_commands
        # print(f"Server starting with allowed commands: {ALLOWED_COMMANDS}", file=sys.stderr)

    if args.restricted_commands is not None:
        # If user explicitly provided restricted commands, we respect that list BUT forcedly include REQUIRED ones.
        # This implies user can only opt-out of OPTIONAL restrictions (filesystem), not REQUIRED ones.
        RESTRICTED_COMMANDS = list(set(REQUIRED_RESTRICTED_COMMANDS + args.restricted_commands))
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
