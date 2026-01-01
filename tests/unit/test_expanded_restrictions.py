import unittest
from pathlib import Path
from mcp_server_for_powershell.server import _validate_command, DEFAULT_RESTRICTED_COMMANDS

class TestExpandedRestrictions(unittest.TestCase):
    def test_service_management_restricted(self):
        restricted = [
            "Start-Service", "sasv",
            "Stop-Service", "spsv",
            "Restart-Service",
            "Suspend-Service", "ssv",
            "Resume-Service",
            "Set-Service",
            "New-Service",
            "Remove-Service"
        ]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd)

    def test_module_management_restricted(self):
        restricted = [
            "Install-Module",
            "Uninstall-Module",
            "Update-Module",
            "Save-Module",
            "Publish-Module"
        ]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd)

    def test_system_config_restricted(self):
        restricted = [
            "Add-Computer", "Remove-Computer", "Rename-Computer", "Join-Domain",
            "Enable-PSRemoting", "Disable-PSRemoting"
        ]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd)
                
    def test_job_management_restricted(self):
        restricted = ["Start-Job", "Stop-Job", "Remove-Job", "Debug-Job"]
        for cmd in restricted:
             with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd)

    def test_network_calls_allowed(self):
        allowed = [
            "Invoke-WebRequest", "iwr", "curl", "wget",
            "Invoke-RestMethod", "irm",
            "Test-Connection", "ping"
        ]
        
        # Ensure these are NOT in the restricted list
        for cmd in allowed:
            self.assertNotIn(cmd, DEFAULT_RESTRICTED_COMMANDS)
            
            # Should NOT raise ValueError
            try:
                _validate_command(cmd)
            except ValueError:
                self.fail(f"{cmd} raised ValueError unexpectedly!")

if __name__ == '__main__':
    unittest.main()
