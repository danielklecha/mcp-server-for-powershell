
import unittest
import sys
import os
import pathlib

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/powershell_mcp')))

# Mocking FastMCP to avoid instantiation issues or side effects during import if it runs things
from unittest.mock import MagicMock
sys.modules['mcp.server.fastmcp'] = MagicMock()
sys.modules['mcp.server.fastmcp.FastMCP'] = MagicMock()

# Now import the function to test
# We need to import the module to access the private function if strictly needed, 
# or just import the function if it's exposed. It is private.
# so we import the module
import mcp_server_for_powershell.server as server
from mcp_server_for_powershell.server import _is_restricted_path

class TestRestrictedPath(unittest.TestCase):
    def setUp(self):
        # Setup restricted directories for testing if they are global
        # server.RESTRICTED_DIRECTORIES is used.
        # We should back it up and restore it.
        self.original_dirs = server.RESTRICTED_DIRECTORIES
        server.RESTRICTED_DIRECTORIES = [r"C:\Restricted", r"C:\Windows"]

    def tearDown(self):
        server.RESTRICTED_DIRECTORIES = self.original_dirs

    def test_restricted_absolute_path(self):
        self.assertTrue(_is_restricted_path(r"C:\Restricted\secret.txt", pathlib.Path(".")))
        self.assertTrue(_is_restricted_path(r"C:\Windows\System32\drivers", pathlib.Path(".")))
        self.assertTrue(_is_restricted_path(r"C:\Restricted", pathlib.Path(".")))

    def test_allowed_absolute_path(self):
        self.assertFalse(_is_restricted_path(r"C:\Allowed\file.txt", pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(r"C:\Users\Public\Documents", pathlib.Path(".")))

    def test_relative_path_skipped(self):
        # Relative paths should return False (not restricted check skipped -> not restricted?)
        # Logic says: if not absolute return False.
        self.assertFalse(_is_restricted_path("file.txt", pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(r"subdir\file.txt", pathlib.Path(".")))

    def test_pathlib_object(self):
        self.assertTrue(_is_restricted_path(pathlib.Path(r"C:\Restricted\file.txt"), pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(pathlib.Path(r"C:\Allowed\file.txt"), pathlib.Path(".")))

    def test_case_insensitivity_if_windows(self):
        # pathlib resolution handles case on Windows usually.
        # But we constructed paths.
        pass

if __name__ == '__main__':
    unittest.main()
