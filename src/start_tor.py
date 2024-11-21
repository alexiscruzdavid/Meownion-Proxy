import subprocess
import time
import socket
from onion_relay import OnionRelay
from tor_encryption import encrypt_message_with_circuit
from onion_directory import OnionDirectory
from onion_proxy import OnionProxy
from random import choice
NUMER_OF_RELAYS = 5
MAX_RELAYS = 30
MAX_CLIENTS = 30
START_PORT = 32200
END_PORT = START_PORT + 5
PROXY_PORT = END_PORT + 1

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


# Construct the path to the Flask application script

# Start the Flask server by directly running the script
process = subprocess.Popen(
    ["python3", "-m", "onion_directory_server"],
    cwd="/home/adc94/Simple-Tor/src",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# Allow some time for the server to start
time.sleep(1)

# Ensure the server is reachable before proceeding with tests
if not is_server_reachable(retries=2):
    process.terminate()
    print("Flask server could not be started. Exiting tests.")
    exit()
    

onion_relays = []

for port in range(START_PORT, END_PORT):
    onion_relays.append(OnionRelay('{}:{}'.format('127.0.0.1',port), '127.0.0.1', port))
    onion_relays[port-START_PORT].start()



if __name__ == '__main__':
    
    op = OnionProxy('127.0.0.1', PROXY_PORT)
    op_states = op.get_states()
    op_dest_port = op.get_destination_port()
    
    dest_state_index = None
    for i in range(len(op_states)):
        if op_states[i]['port'] == op_dest_port:
            dest_state_index = i
          
    circuit = []
    for i in range(3):
        curr_relay_index = choice([relay_index for relay_index in range(0,len(op_states)) if relay_index != dest_state_index])
        circuit.append(op_states[curr_relay_index])
    
    op.start(circuit)
    
    