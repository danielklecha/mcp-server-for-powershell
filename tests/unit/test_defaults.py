import os
import pathlib
import sys
import unittest

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

# Mock FastMCP
# Mock FastMCP
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

from mcp_server_for_powershell import server


class TestDefaults(unittest.TestCase):
    def test_default_restricted_directories(self):
        defaults = server._get_default_restricted_directories()

        if os.name == "nt":
            self.assertIn(r"C:\Windows", defaults)
            self.assertIn(r"C:\Program Files", defaults)
        else:
            self.assertIn("/etc", defaults)
            self.assertIn("/root", defaults)
            # Ensure windows paths are NOT in defaults for linux
            self.assertNotIn(r"C:\Windows", defaults)


if __name__ == "__main__":
    unittest.main()
