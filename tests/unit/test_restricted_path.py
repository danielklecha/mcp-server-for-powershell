import os
import pathlib
import sys
import unittest

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Mocking FastMCP to avoid instantiation issues or side effects during import if it runs things
from unittest.mock import MagicMock

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

# Now import the function to test
# We need to import the module to access the private function if strictly needed,
# or just import the function if it's exposed. It is private.
# so we import the module
from mcp_server_for_powershell import server
from mcp_server_for_powershell.server import _is_restricted_path


class TestRestrictedPath(unittest.TestCase):
    def setUp(self):
        # Setup restricted directories for testing based on OS
        self.original_dirs = server.RESTRICTED_DIRECTORIES

        if os.name == "nt":
            self.restricted_root = r"C:\Restricted"
            self.windows_system = r"C:\Windows"
            self.allowed_root = r"C:\Allowed"
            self.public_docs = r"C:\Users\Public\Documents"
            server.RESTRICTED_DIRECTORIES = [self.restricted_root, self.windows_system]
        else:
            # POSIX paths for Linux execution (GitHub Actions)
            self.restricted_root = "/tmp/Restricted"
            self.windows_system = "/etc"  # acting as a system dir
            self.allowed_root = "/tmp/Allowed"
            self.public_docs = "/home/user/public"
            server.RESTRICTED_DIRECTORIES = [self.restricted_root, self.windows_system]

    def tearDown(self):
        server.RESTRICTED_DIRECTORIES = self.original_dirs

    def test_restricted_absolute_path(self):
        # Construct paths using the roots defined in setUp
        secret_txt = os.path.join(self.restricted_root, "secret.txt")
        system_file = os.path.join(self.windows_system, "System32", "drivers")

        self.assertTrue(_is_restricted_path(secret_txt, pathlib.Path(".")))
        self.assertTrue(_is_restricted_path(system_file, pathlib.Path(".")))
        self.assertTrue(_is_restricted_path(self.restricted_root, pathlib.Path(".")))

    def test_allowed_absolute_path(self):
        allowed_file = os.path.join(self.allowed_root, "file.txt")

        self.assertFalse(_is_restricted_path(allowed_file, pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(self.public_docs, pathlib.Path(".")))

    def test_relative_path_skipped(self):
        # Relative paths should return False (checks against restricted dirs are for absolute paths)
        self.assertFalse(_is_restricted_path("file.txt", pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(os.path.join("subdir", "file.txt"), pathlib.Path(".")))

    def test_pathlib_object(self):
        restricted_file = pathlib.Path(self.restricted_root) / "file.txt"
        allowed_file = pathlib.Path(self.allowed_root) / "file.txt"

        self.assertTrue(_is_restricted_path(restricted_file, pathlib.Path(".")))
        self.assertFalse(_is_restricted_path(allowed_file, pathlib.Path(".")))

    def test_case_insensitivity_if_windows(self):
        if os.name == "nt":
            # Check mixed case on Windows
            mixed_case = self.restricted_root.lower()
            self.assertTrue(_is_restricted_path(mixed_case, pathlib.Path(".")))
        else:
            pass


if __name__ == "__main__":
    unittest.main()
