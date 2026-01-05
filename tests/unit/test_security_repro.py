import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
from mcp_server_for_powershell import server


class TestSecurityRepro(unittest.TestCase):
    def setUp(self):
        self.cwd = pathlib.Path(os.getcwd())
        # Ensure regex is in restricted commands (it is default, but just to be sure context is clean)
        # Force reload default restricts in case previous tests messed it up
        server.RESTRICTED_COMMANDS = server._get_default_restricted_commands()

    def test_shell_variants_blocked(self):
        """Verify that shell variants are blocked."""
        if os.name == "nt":
            variants = [
                "pwsh.exe",
                "powershell.exe",
                "cmd.exe",
                "CMD.EXE",
                r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ]
            for cmd in variants:
                with self.assertRaises(ValueError, msg=f"Variant '{cmd}' should be blocked"):
                    server._validate_command(cmd, self.cwd)

    def test_lolbins_blocked(self):
        """Verify that newly added LOLBins are blocked."""
        if os.name == "nt":
            lolbins = ["MSBuild.exe", "InstallUtil.exe", "regasm.exe", "mshta.exe"]
            for cmd in lolbins:
                with self.assertRaises(ValueError, msg=f"LOLBin '{cmd}' should be blocked"):
                    server._validate_command(cmd, self.cwd)


if __name__ == "__main__":
    unittest.main()
