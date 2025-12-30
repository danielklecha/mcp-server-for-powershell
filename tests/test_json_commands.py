import unittest
import json
import base64
from unittest.mock import patch, MagicMock
import sys
import os
import pathlib

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/powershell_mcp')))

from mcp_server_for_powershell.server import run_powershell, _construct_script
import mcp_server_for_powershell.server as server_module

class TestJsonCommands(unittest.TestCase):
    
    def setUp(self):
        # Reset the global variable before each test
        server_module.LANGUAGE_MODE = 1

    def test_construct_single_command(self):
        input_data = [{"command": "Get-Item", "parameters": ["."]}]
        result = _construct_script(input_data, pathlib.Path("."))
        # Expected: Get-Item '.'
        self.assertEqual(result, "Get-Item '.'")

    def test_construct_dotnet_method(self):
        input_data = [{"command": "[System.Math]::Sqrt", "parameters": [16]}]
        result = _construct_script(input_data, pathlib.Path("."))
        # Expected: [System.Math]::Sqrt(16)
        self.assertEqual(result, "[System.Math]::Sqrt(16)")

    def test_construct_dotnet_method_multiple_args(self):
        # Hypothetical method with multiple args
        input_data = [{"command": "[Some.Class]::Method", "parameters": [1, "two", True]}]
        result = _construct_script(input_data, pathlib.Path("."))
        # Expected: [Some.Class]::Method(1, 'two', $true)
        self.assertEqual(result, "[Some.Class]::Method(1, 'two', $true)")

    @patch('mcp_server_for_powershell.server.subprocess.Popen')
    def test_run_powershell_simple(self, mock_popen):
        # Mock process output
        process_mock = MagicMock()
        process_mock.communicate.return_value = ("Success", "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        json_input = json.dumps([{"command": "Get-Date"}])
        result = run_powershell(json=json_input)
        
        self.assertEqual(result, "Success")
        
        # Verify the command passed to pwsh
        args, kwargs = mock_popen.call_args
        cmd_list = args[0]
        self.assertIn("pwsh", cmd_list)
        self.assertIn("-EncodedCommand", cmd_list)
        
        # Decode and verify content
        encoded = cmd_list[cmd_list.index("-EncodedCommand") + 1]
        decoded_bytes = base64.b64decode(encoded)
        decoded_script = decoded_bytes.decode('utf-16le')
        
        # Verify language mode and command
        self.assertIn('$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"; ', decoded_script)
        self.assertIn("Get-Date", decoded_script)

    @patch('mcp_server_for_powershell.server.subprocess.Popen')
    def test_run_powershell_disable_restricted(self, mock_popen):
        # Temporarily disable restricted language (FullLanguage)
        server_module.LANGUAGE_MODE = 3
        
        process_mock = MagicMock()
        process_mock.communicate.return_value = ("Success", "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        json_input = json.dumps([{"command": "Get-Date"}])
        result = run_powershell(json=json_input)
        
        args, kwargs = mock_popen.call_args
        cmd_list = args[0]
        encoded = cmd_list[cmd_list.index("-EncodedCommand") + 1]
        decoded_bytes = base64.b64decode(encoded)
        decoded_script = decoded_bytes.decode('utf-16le')
        
        # Verify language mode is NOT prepended
        self.assertFalse(decoded_script.startswith('$ExecutionContext.SessionState.LanguageMode = "RestrictedLanguage"; '))
        self.assertIn("Get-Date", decoded_script)

    @patch('mcp_server_for_powershell.server.subprocess.Popen')
    def test_construction_named_params(self, mock_popen):
        process_mock = MagicMock()
        process_mock.communicate.return_value = ("", "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        # {command: "", parameters: { "-Headers": "x" }}
        json_input = json.dumps([{
            "command": "Get-Item", 
            "parameters": {"-Path": ".", "-Force": True}
        }])
        
        run_powershell(json=json_input)
        
        args, _ = mock_popen.call_args
        encoded = args[0][args[0].index("-EncodedCommand") + 1]
        decoded = base64.b64decode(encoded).decode('utf-16le')
        
        self.assertIn("Get-Item", decoded)
        self.assertIn("-Path '.'", decoded)
        self.assertIn("-Force $true", decoded)

    @patch('mcp_server_for_powershell.server.subprocess.Popen')
    def test_pipeline(self, mock_popen):
        process_mock = MagicMock()
        process_mock.communicate.return_value = ("", "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        # {command: "A", then: {command: "B"}}
        json_input = json.dumps([{
            "command": "Get-Process",
            "then": {"command": "Select-Object", "parameters": ["Name"]}
        }])
        
        run_powershell(json=json_input)
        
        args, _ = mock_popen.call_args
        encoded = args[0][args[0].index("-EncodedCommand") + 1]
        decoded = base64.b64decode(encoded).decode('utf-16le')
        
        self.assertIn("Get-Process | Select-Object 'Name'", decoded)

    @patch('mcp_server_for_powershell.server.subprocess.Popen')
    def test_sequence(self, mock_popen):
        process_mock = MagicMock()
        process_mock.communicate.return_value = ("", "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        # [{cmd: A}, {cmd: B}]
        json_input = json.dumps([
            {"command": "Get-Date", "parameters": []},
            {"command": "Get-Location", "parameters": []}
        ])
        
        run_powershell(json=json_input)
        
        args, _ = mock_popen.call_args
        encoded = args[0][args[0].index("-EncodedCommand") + 1]
        decoded = base64.b64decode(encoded).decode('utf-16le')
        
        self.assertTrue("; " in decoded or "\n" in decoded)
        self.assertIn("Get-Date", decoded)
        self.assertIn("Get-Location", decoded)

if __name__ == '__main__':
    unittest.main()
