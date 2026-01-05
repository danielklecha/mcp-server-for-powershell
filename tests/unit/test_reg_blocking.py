import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
from mcp_server_for_powershell import server


class TestRegExeBlocking(unittest.TestCase):
    def setUp(self):
        self.cwd = pathlib.Path(os.getcwd())
        # Ensure regex is in restricted commands (it is default, but just to be sure context is clean)
        server.RESTRICTED_COMMANDS = server.DEFAULT_RESTRICTED_COMMANDS

    def test_reg_variants_blocked(self):
        """Verify that various forms of reg.exe are blocked."""

        variants = [
            "reg.exe",
            "reg",
            r"C:\Windows\reg.exe",
            r"C:\Windows\System32\reg.exe",
            r".\reg.exe",
            r"..\reg.exe",
            r"C:\MyCustomPath\reg.exe",
            "REG.EXE",
            "Reg.Exe",
        ]

        if os.name == "nt":
            for cmd in variants:
                with self.assertRaises(ValueError, msg=f"Variant '{cmd}' should be blocked"):
                    server._validate_command(cmd, self.cwd)

    def test_other_restricted_variants(self):
        """Verify other restricted critical commands."""
        if os.name == "nt":
            variants = ["cmd.exe", "powershell.exe", "pwsh.exe", r"C:\Windows\System32\cmd.exe"]
            for cmd in variants:
                with self.assertRaises(ValueError, msg=f"Variant '{cmd}' should be blocked"):
                    server._validate_command(cmd, self.cwd)


if __name__ == "__main__":
    unittest.main()
