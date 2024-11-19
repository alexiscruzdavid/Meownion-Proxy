import os
import subprocess

import requests
import pytest
import time
import socket
from src.onion_relay import OnionRelay
from src.onion_directory import OnionDirectory


@pytest.fixture(scope="session")
def onion_relay():
    return OnionRelay(
        name="TestRelay",
        ip="127.0.0.1",
        port=7000,
    )


@pytest.fixture(scope="session", autouse=True)
def start_flask_server():
    # Construct the path to the Flask application script

    # Start the Flask server by directly running the script
    process = subprocess.Popen(
        ["python3", "-m", "src.onion_directory_server"],
        cwd="/Users/marcusortiz/Projects/Distributed/Simple-Tor",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Allow some time for the server to start
    time.sleep(1)

    # Ensure the server is reachable before proceeding with tests
    if not is_server_reachable(retries=2):
        process.terminate()
        pytest.exit("Flask server could not be started. Exiting tests.")

    # The server will continue to run for the entire test session
    yield

    # Terminate the server process after the tests are done
    process.terminate()
    process.wait()


def is_server_reachable(host="127.0.0.1", port=8001, retries=0, delay=1):
    """
    Check if the server is reachable with retries and delays
    """
    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except (socket.timeout, ConnectionRefusedError):
            if attempt < retries - 1:
                time.sleep(delay)  # Wait before retrying
            else:
                return False
    return False


def test_upload_state_integration(onion_relay):
    """
    Integration test for the `upload_state` function using actual certificate methods.
    """
    assert onion_relay.upload_state() == True


def test_download_states_integration(onion_relay):
    """
    Integration test for the `update_connections` function using actual server.
    """
    if not onion_relay.upload_state():
        pytest.skip("Skipping test as relay could not be uploaded")
    time.sleep(1)

    states = onion_relay.download_states()

    assert states is not None and len(states) > 0

    for state in states:
        assert "ip" in state
        assert "port" in state
        assert isinstance(state["ip"], str)
        assert isinstance(state["port"], int)


def test_heartbeat_integration(onion_relay):
    """
    Integration test for the `heartbeat` function using actual certificates.
    """
    """
        Integration test for the `upload_state` function using actual certificate methods.
        """
    if not onion_relay.upload_state():
        pytest.skip("Skipping test as relay could not be uploaded")
    time.sleep(1)

    # Test single heartbeat
    assert onion_relay.heartbeat()
