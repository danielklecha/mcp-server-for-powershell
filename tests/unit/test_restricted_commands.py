import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

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


class TestRestrictedCommands(unittest.TestCase):
    def setUp(self):
        # Store original values
        self.original_restricted = server.RESTRICTED_COMMANDS
        self.original_defaults = server.DEFAULT_RESTRICTED_COMMANDS
        self.cwd = pathlib.Path(os.getcwd())

        # Reset to defaults
        server.RESTRICTED_COMMANDS = list(server.DEFAULT_RESTRICTED_COMMANDS)

    def tearDown(self):
        # Restore original values
        server.RESTRICTED_COMMANDS = self.original_restricted
        server.DEFAULT_RESTRICTED_COMMANDS = self.original_defaults

    def test_default_restrictions_contain_key_commands(self):
        # Check for items that should be restricted
        self.assertIn("Invoke-Expression", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertIn("Start-Process", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertIn("Remove-Item", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertIn("Set-Content", server.DEFAULT_RESTRICTED_COMMANDS)

    def test_new_security_restrictions(self):
        # Verify new mandatory restrictions are present
        self.assertIn("Get-Clipboard", server.DEFAULT_RESTRICTED_COMMANDS)
        if os.name == "nt":
            self.assertIn("Set-ExecutionPolicy", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertIn("Get-Variable", server.DEFAULT_RESTRICTED_COMMANDS)

        # Verify Drive Management restrictions
        self.assertIn("New-PSDrive", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertIn("Remove-PSDrive", server.DEFAULT_RESTRICTED_COMMANDS)

        # Verify network requests are still ALLOWED (NOT in restricted list)
        self.assertNotIn("Invoke-WebRequest", server.DEFAULT_RESTRICTED_COMMANDS)
        self.assertNotIn("iwr", server.DEFAULT_RESTRICTED_COMMANDS)

    def test_validate_command_blocks_restricted(self):
        # Test default blocking
        with self.assertRaises(ValueError) as cm:
            server._validate_command("Invoke-Expression", self.cwd)
        self.assertIn("restricted", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            server._validate_command(".", self.cwd)
        self.assertIn("restricted", str(cm.exception))

    def test_validate_command_allows_safe(self):
        # Test safe command
        try:
            server._validate_command("Get-Date", self.cwd)
        except ValueError:
            self.fail("Get-Date raised ValueError unexpectedly!")

    def test_validate_command_logs_when_blocked(self):
        # Ensure logger.warning is called when a command is blocked
        with patch("mcp_server_for_powershell.server.logger") as mock_logger:
            with self.assertRaises(ValueError):
                server._validate_command("Invoke-Expression", self.cwd)
            mock_logger.warning.assert_called()

    def test_override_restrictions_empty(self):
        # Simulate --restricted-commands (empty logic)
        # Verify that clearing the list allows previously restricted commands
        server.RESTRICTED_COMMANDS = []

        try:
            server._validate_command("Invoke-Expression", self.cwd)
        except ValueError:
            self.fail("Invoke-Expression raised ValueError even though restricted list is empty!")

    def test_override_restrictions_custom(self):
        # Simulate --restricted-commands Get-Date
        server.RESTRICTED_COMMANDS = ["Get-Date"]

        # Now Invoke-Expression should be allowed
        try:
            server._validate_command("Invoke-Expression", self.cwd)
        except ValueError:
            self.fail("Invoke-Expression raised ValueError with custom restriction list!")

        # And Get-Date should be blocked
        with self.assertRaises(ValueError) as cm:
            server._validate_command("Get-Date", self.cwd)
        self.assertIn("restricted", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
