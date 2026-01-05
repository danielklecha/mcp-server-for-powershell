import os
import sys
import unittest
from pathlib import Path

# Adjust path to import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))

from mcp_server_for_powershell.server import DEFAULT_RESTRICTED_COMMANDS, _validate_command


class TestExpandedRestrictions(unittest.TestCase):
    def setUp(self):
        self.cwd = Path.cwd()

    def test_service_management_restricted(self):
        # Service management commands are only restricted on Windows
        if os.name != "nt":
            return

        restricted = [
            "Start-Service",
            "sasv",
            "Stop-Service",
            "spsv",
            "Restart-Service",
            "Suspend-Service",
            "ssv",
            "Resume-Service",
            "Set-Service",
            "New-Service",
            "Remove-Service",
        ]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd, self.cwd)

    def test_module_management_restricted(self):
        restricted = ["Install-Module", "Uninstall-Module", "Update-Module", "Save-Module", "Publish-Module"]
        # Additional module/script/package management commands that must be restricted
        restricted.extend(
            [
                "Import-Module",
                "Remove-Module",
                "Add-PSSnapin",
                "Remove-PSSnapin",
                "Install-Script",
                "Save-Script",
                "Uninstall-Script",
                "Install-Package",
                "Uninstall-Package",
                # Package provider / package discovery
                "Install-PackageProvider",
                "Save-Package",
                "Find-Package",
                # Additional package provider/source management
                "Find-PackageProvider",
                "Get-PackageProvider",
                "Uninstall-PackageProvider",
                "Get-Package",
                "Get-PackageSource",
                "Register-PackageSource",
                "Unregister-PackageSource",
            ]
        )
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd, self.cwd)

    def test_system_config_restricted(self):
        # System configuration commands are only restricted on Windows
        if os.name != "nt":
            return

        restricted = [
            "Add-Computer",
            "Remove-Computer",
            "Rename-Computer",
            "Join-Domain",
            "Enable-PSRemoting",
            "Disable-PSRemoting",
        ]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd, self.cwd)

    def test_job_management_restricted(self):
        restricted = ["Start-Job", "Stop-Job", "Remove-Job", "Debug-Job"]
        for cmd in restricted:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd, self.cwd)

    def test_network_calls_allowed(self):
        allowed = ["Invoke-WebRequest", "iwr", "curl", "wget", "Invoke-RestMethod", "irm", "Test-Connection", "ping"]

        # Ensure these are NOT in the restricted list
        for cmd in allowed:
            self.assertNotIn(cmd, DEFAULT_RESTRICTED_COMMANDS)

            # Should NOT raise ValueError
            try:
                _validate_command(cmd, self.cwd)
            except ValueError:
                self.fail(f"{cmd} raised ValueError unexpectedly!")

    def test_bits_transfer_restricted(self):
        # BITS transfers should be restricted as they can download/upload files silently
        with self.assertRaises(ValueError, msg="Start-BitsTransfer should be restricted"):
            _validate_command("Start-BitsTransfer", self.cwd)

    def test_native_network_utilities_restricted(self):
        # Native OS utilities that can transfer files or install packages should be restricted
        # This test is only relevant on Windows where these utilities are common/restricted by default
        if os.name != "nt":
            return

        restricted_native = [
            "certutil",
            "certutil.exe",
            "bitsadmin",
            "bitsadmin.exe",
            "msiexec",
            "msiexec.exe",
            "ftp",
            "ftp.exe",
            "tftp",
            "tftp.exe",
            "curl.exe",
            "wget.exe",
        ]
        for cmd in restricted_native:
            with self.assertRaises(ValueError, msg=f"{cmd} should be restricted"):
                _validate_command(cmd, self.cwd)


if __name__ == "__main__":
    unittest.main()
