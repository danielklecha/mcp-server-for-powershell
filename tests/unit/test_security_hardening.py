import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Mock FastMCP
mock_mcp_instance = MagicMock()


def tool_decorator():
    def decorator(func):
        return func

    return decorator


mock_mcp_instance.tool.side_effect = tool_decorator

mock_fastmcp_cls = MagicMock(return_value=mock_mcp_instance)
mock_module = MagicMock()
mock_module.FastMCP = mock_fastmcp_cls
sys.modules["mcp.server.fastmcp"] = mock_module

from mcp_server_for_powershell import server


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.original_restricted_dirs = server.RESTRICTED_DIRECTORIES
        self.cwd = pathlib.Path(os.getcwd())

    def tearDown(self):
        server.RESTRICTED_DIRECTORIES = self.original_restricted_dirs

    def test_restricted_drives_blocked(self):
        """Verify that PowerShell drives are blocked by prefix check."""

        # Test common cross-platform drive match
        self.assertTrue(server._is_restricted_path("Env:", self.cwd), "Env: should be restricted on all platforms")
        self.assertTrue(server._is_restricted_path("Env:\\Path", self.cwd), "Env:\\Path should be restricted")

        # Test case insensitivity (common)
        self.assertTrue(
            server._is_restricted_path("env:\\path", self.cwd), "env:\\path should be restricted (case-insensitive)"
        )

        # Test Windows-specific drives only on Windows
        if os.name == "nt":
            self.assertTrue(server._is_restricted_path("HKLM:", self.cwd), "HKLM: should be restricted on Windows")
            self.assertTrue(
                server._is_restricted_path("HKLM:\\Software", self.cwd), "HKLM:\\Software should be restricted"
            )
            self.assertTrue(
                server._is_restricted_path("Cert:\\LocalMachine", self.cwd), "Cert:\\LocalMachine should be restricted"
            )

    def test_allowed_paths(self):
        """Verify that normal paths are not falsely restricted."""

        # Current directory or innocuous paths should be allowed (assuming they aren't system dirs)
        # We need a path that definitely isn't in C:\Windows or similar checks
        safe_path = "C:\\Temp\\SafeProject"

        # Mocking or ensuring we don't accidentally hit a real restricted dir on the test runner
        # Since _check_restricted iterates default list, and C:\Temp is usually fine.

        self.assertFalse(server._is_restricted_path(safe_path, self.cwd), f"{safe_path} should be allowed")

        # Single letter drives (if checking for C:) usually allowed unless it resolves to restricted content
        self.assertFalse(
            server._is_restricted_path("C:", self.cwd),
            "C: drive root itself usually allowed unless explicitly blocked or resolves to restricted",
        )

    def test_network_commands_allowed(self):
        """Verify that network commands are safely allowed (not in restricted list)."""
        network_cmds = ["Invoke-WebRequest", "Invoke-RestMethod", "Test-Connection"]
        for cmd in network_cmds:
            try:
                server._validate_command(cmd, self.cwd)
            except ValueError:
                self.fail(f"{cmd} should be allowed but raised ValueError")

    def test_extended_restrictions(self):
        """Verify newly added restricted commands are blocked."""
        new_restrictions = [
            "Export-Csv",
            "Read-Host",
            "New-Object",
            "Out-GridView",
            "Invoke-CimMethod",
            "Expand-Archive",
            "Compress-Archive",
            "Start-Transcript",
            "Set-Variable",
            "Enter-PSHostProcess",
        ]
        # Also prevent adding package repositories/repo registration
        new_restrictions.extend(["Register-PSRepository", "Register-PSResourceRepository", "Set-PSRepository"])

        if os.name == "nt":
            new_restrictions.extend(
                [
                    "Format-Volume",
                    "Clear-Disk",  # Disk
                    "Set-Acl",
                    "Unblock-File",  # Security
                    "reg.exe",
                    "net.exe",
                    "netsh",  # Native
                    "schtasks",
                    "vssadmin",
                    "Set-ItemProperty",
                    "New-LocalUser",  # Registry & User
                    "Set-MpPreference",
                    "New-NetFirewallRule",  # Defender/Firewall
                    "Register-ScheduledTask",
                    "Export-PfxCertificate",  # Tasks/Certs
                    "taskkill.exe",
                ]
            )
        for cmd in new_restrictions:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                server._validate_command(cmd, self.cwd)

            # Case insensitivity check
            with self.assertRaises(ValueError, msg=f"{cmd.upper()} should be restricted"):
                server._validate_command(cmd.upper(), self.cwd)

    def test_allowed_overrides_restricted(self):
        """Verify that explicit allowed commands override default restrictions."""
        # Simulate server started with --allowed-commands Set-Content
        original_allowed = server.ALLOWED_COMMANDS
        server.ALLOWED_COMMANDS = ["Set-Content"]
        # Ensure Restricted is default
        server.RESTRICTED_COMMANDS = None

        try:
            # Should pass if logic is updated, currently fails
            server._validate_command("Set-Content", self.cwd)
        except ValueError:
            self.fail("Set-Content should be allowed if explicitly in ALLOWED_COMMANDS")
        finally:
            server.ALLOWED_COMMANDS = original_allowed

    def test_command_canonicalization_and_path_variants(self):
        """Verify that command paths and casing are canonicalized so restrictions apply."""
        # certutil.exe is in default restricted list on Windows
        if os.name == "nt":
            # 1. Full path
            cmd_path = r"C:\Windows\System32\certutil.exe"
            with self.assertRaises(ValueError, msg="Full path to certutil.exe should be blocked"):
                server._validate_command(cmd_path, self.cwd)

            # 2. Mixed case full path
            cmd_path_mixed = r"C:\WINDOWS\System32\CERTUTIL.EXE"
            with self.assertRaises(ValueError, msg="Mixed case path to certutil.exe should be blocked"):
                server._validate_command(cmd_path_mixed, self.cwd)

            # 3. Just filename variations
            with self.assertRaises(ValueError):
                server._validate_command("CERTUTIL.EXE", self.cwd)

            # 4. Check that similar looking commands are NOT blocked if legal (e.g. mycertutil.exe)
            # Assuming mycertutil.exe is not restricted
            try:
                server._validate_command("mycertutil.exe", self.cwd)  # Should pass
            except ValueError:
                self.fail("mycertutil.exe should not be blocked")

    def test_explicit_path_restriction(self):
        """Verify that any command (even allowed names) is blocked if in restricted dir."""
        if os.name != "nt":
            return

        # "ping.exe" is usually allowed. But if we try to run it via Explicit Path to C:\Windows\System32...
        # It is now BLOCKED because C:\Windows is restricted.
        # This forces users to use PATH lookup (implicit trust of system config) or trusted dirs.

        cmd_path = r"C:\Windows\System32\ping.exe"

        # Ensure ping is NOT in restricted commands (it's not by default)

        with self.assertRaises(
            ValueError, msg=f"Explicit path {cmd_path} should be blocked due to directory restriction"
        ):
            server._validate_command(cmd_path, self.cwd)

    def test_explicit_path_safe_dir(self):
        """Verify that explicit path in safe dir is allowed."""
        # Assume C:\Temp\Safe is safe
        cmd_path = r"C:\Temp\Safe\mytool.exe"
        try:
            server._validate_command(cmd_path, self.cwd)
        except ValueError as e:
            self.fail(f"Safe path execution failed: {e}")

    def test_allowed_overrides_path_restriction(self):
        """Verify that ALLOWED_COMMANDS overrides even the path check."""
        if os.name != "nt":
            return

        cmd_path = r"C:\Windows\System32\ping.exe"

        # Explicitly allow this specific path/command
        original_allowed = server.ALLOWED_COMMANDS
        # The allow list checks against canonical name (basename lower)
        # So if we allow "ping.exe", does it allow "C:\Windows\System32\ping.exe"?
        # Current logic: _canonicalize(cmd_name) -> "ping.exe".
        # If "ping.exe" in ALLOWED, we return immediately.

        server.ALLOWED_COMMANDS = ["ping.exe"]
        try:
            server._validate_command(cmd_path, self.cwd)
        except ValueError:
            self.fail("Explicitly allowed command should pass even if path is restricted")
        finally:
            server.ALLOWED_COMMANDS = original_allowed

    def test_restricted_directory_case_insensitivity(self):
        """Verify that directory restrictions are case-insensitive on Windows."""
        if os.name != "nt":
            return

        # C:\Windows is restricted by default on Windows

        # 1. Valid case
        self.assertTrue(
            server._is_restricted_path(r"C:\Windows\System32", self.cwd),
            "Standard C:\\Windows path should be restricted",
        )

        # 2. Lowercase
        self.assertTrue(
            server._is_restricted_path(r"c:\windows\system32", self.cwd), "Lowercase c:\\windows should be restricted"
        )

        # 3. Mixed case
        self.assertTrue(
            server._is_restricted_path(r"C:\WiNdOwS\SyStEm32", self.cwd), "Mixed case C:\\WiNdOwS should be restricted"
        )

        # 4. Complex path with dots
        complex_path = r"C:\Users\..\Windows\System32"
        self.assertTrue(
            server._is_restricted_path(complex_path, self.cwd), "Path resolving to Windows via .. should be restricted"
        )


if __name__ == "__main__":
    unittest.main()
