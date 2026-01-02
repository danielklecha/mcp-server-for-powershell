import unittest
from unittest.mock import MagicMock
import sys
import os
import pathlib

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

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
sys.modules['mcp.server.fastmcp'] = mock_module

import mcp_server_for_powershell.server as server

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
        self.assertTrue(server._is_restricted_path("env:\\path", self.cwd), "env:\\path should be restricted (case-insensitive)")
        
        # Test Windows-specific drives only on Windows
        if os.name == 'nt':
            self.assertTrue(server._is_restricted_path("HKLM:", self.cwd), "HKLM: should be restricted on Windows")
            self.assertTrue(server._is_restricted_path("HKLM:\\Software", self.cwd), "HKLM:\\Software should be restricted")
            self.assertTrue(server._is_restricted_path("Cert:\\LocalMachine", self.cwd), "Cert:\\LocalMachine should be restricted")

    def test_allowed_paths(self):
        """Verify that normal paths are not falsely restricted."""
        
        # Current directory or innocuous paths should be allowed (assuming they aren't system dirs)
        # We need a path that definitely isn't in C:\Windows or similar checks
        safe_path = "C:\\Temp\\SafeProject"
        
        # Mocking or ensuring we don't accidentally hit a real restricted dir on the test runner
        # Since _check_restricted iterates default list, and C:\Temp is usually fine.
        
        self.assertFalse(server._is_restricted_path(safe_path, self.cwd), f"{safe_path} should be allowed")
        
        # Single letter drives (if checking for C:) usually allowed unless it resolves to restricted content
        self.assertFalse(server._is_restricted_path("C:", self.cwd), "C: drive root itself usually allowed unless explicitly blocked or resolves to restricted")

    def test_network_commands_allowed(self):
        """Verify that network commands are safely allowed (not in restricted list)."""
        network_cmds = ["Invoke-WebRequest", "Invoke-RestMethod", "Test-Connection"]
        for cmd in network_cmds:
            try:
                server._validate_command(cmd)
            except ValueError:
                self.fail(f"{cmd} should be allowed but raised ValueError")

    def test_extended_restrictions(self):
        """Verify newly added restricted commands are blocked."""
        new_restrictions = [
            "Export-Csv", "Read-Host", "New-Object", "Out-GridView", "Invoke-CimMethod",
            "Expand-Archive", "Compress-Archive", "Start-Transcript", "Set-Variable", "Enter-PSHostProcess"
        ]
        
        if os.name == 'nt':
            new_restrictions.extend([
                "Format-Volume", "Clear-Disk", # Disk
                "Set-Acl", "Unblock-File",    # Security
                "reg.exe", "net.exe", "netsh", # Native
                "schtasks", "vssadmin",
                "Set-ItemProperty", "New-LocalUser", # Registry & User
                "Set-MpPreference", "New-NetFirewallRule", # Defender/Firewall
                "Register-ScheduledTask", "Export-PfxCertificate", # Tasks/Certs
                "taskkill.exe"
            ])
        for cmd in new_restrictions:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                server._validate_command(cmd)
                
            # Case insensitivity check
            with self.assertRaises(ValueError, msg=f"{cmd.upper()} should be restricted"):
                server._validate_command(cmd.upper())

    def test_allowed_overrides_restricted(self):
        """Verify that explicit allowed commands override default restrictions."""
        # Simulate server started with --allowed-commands Set-Content
        original_allowed = server.ALLOWED_COMMANDS
        server.ALLOWED_COMMANDS = ["Set-Content"]
        # Ensure Restricted is default
        server.RESTRICTED_COMMANDS = None
        
        try:
            # Should pass if logic is updated, currently fails
            server._validate_command("Set-Content")
        except ValueError:
            self.fail("Set-Content should be allowed if explicitly in ALLOWED_COMMANDS")
        finally:
            server.ALLOWED_COMMANDS = original_allowed

if __name__ == '__main__':
    unittest.main()
