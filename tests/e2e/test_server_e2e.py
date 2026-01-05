import json
import os
import subprocess
import sys
import time

import pytest


def test_server_initialization():
    """
    Test that the MCP server starts up and responds to an initialize request.
    This runs the server as a subprocess using the current Python interpreter
    and the source code in ../../src.
    """
    # Path to the src directory
    src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src"))

    # Environment with src in PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = src_path + os.pathsep + env.get("PYTHONPATH", "")

    # Command to run the server module
    command = [sys.executable, "-m", "mcp_server_for_powershell.server"]

    print(f"Starting server with command: {command}")

    # Run the server process
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=0,  # Unbuffered
        env=env,
    )

    try:
        # Wait a moment for startup
        time.sleep(2)

        if process.poll() is not None:
            stderr_output = process.stderr.read()
            pytest.fail(f"Process exited immediately with code {process.returncode}. Stderr: {stderr_output}")

        # Send initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }

        json_str = json.dumps(init_request)
        process.stdin.write(json_str + "\n")
        process.stdin.flush()

        # Read response
        # Using readline() works if the server sends a newline-terminated JSON
        line = process.stdout.readline()

        if not line:
            # Check if process died
            if process.poll() is not None:
                stderr_output = process.stderr.read()
                pytest.fail(f"Process died while waiting for response. Stderr: {stderr_output}")
            pytest.fail("No response received (EOF) but process is still running.")

        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            pytest.fail(f"Received non-JSON response: {line}")

        assert "result" in resp, f"Response did not contain 'result': {resp}"
        # We could inspect capabilities here if needed
        print("Verification SUCCESS: Received initialize result.")

    finally:
        # cleanup
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
