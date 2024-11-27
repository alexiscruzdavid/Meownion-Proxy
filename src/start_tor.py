import subprocess
import time
import threading
import socket
from onion_relay import OnionRelay
from tor_encryption import encrypt_message_with_circuit
from onion_directory import OnionDirectory
from onion_proxy import OnionProxy
from random import choice
import os
import logging 
logging.basicConfig(level=logging.INFO)

NUMER_OF_RELAYS = 5
MAX_RELAYS = 30
MAX_CLIENTS = 30
START_PORT = 23000
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
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
process = subprocess.Popen(
    ["python3", "-m", "onion_directory_server"],
    cwd="{}".format(BASE_DIR),
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
    onion_relays.append(OnionRelay('{}:{}'.format('127.0.0.1', port), '127.0.0.1', port))
    # curr_key_arr = [relay_state['onion_key'].encode('iso-8859-1') for relay_state in onion_relays[port-START_PORT].relay_states if relay_state['port'] == port]
    # onion_relays[port-START_PORT].onion_key = curr_key_arr[0]
    onion_relays[port-START_PORT].start()
    



if __name__ == '__main__':
    
    op = OnionProxy('127.0.0.1', PROXY_PORT)
    op_states = op.get_states()
    op_dest_port = op.get_destination_port()
    # TODO: remove after test
    op_dest_port = START_PORT
    
    dest_state_index = None
    src_state_index = None
    for i in range(len(op_states)):
        if op_states[i]['port'] == op_dest_port:
            dest_state_index = i
        if op_states[i]['port'] == PROXY_PORT:
            src_state_index = i
          
    circuit = []
    for i in range(2):
        curr_relay_index = choice([relay_index for relay_index in range(0,len(op_states)) if (relay_index != dest_state_index and relay_index != src_state_index)])
        circuit.append(op_states[curr_relay_index])
    
    first_relay = op_states[0]
    op.circuit_create_send(0, op.src_port, first_relay['port'])
    time.sleep(5)

    for index, relay_state in enumerate(circuit[1:], start=1):
        print(f"PLEASE MAKE IT STOP PLEASE MAKE IT STOP THE ABD ACTOR IS {relay_state['port']}")
        op.circuit_extend_send(0, relay_state['port'], circuit[:index+1])
        time.sleep(5)
        
    time.sleep(5)
    # op.start(circuit)
    for relay in onion_relays:
        print(f"{relay.name} \n all_circuits: {relay.all_circuits} \n circuit_forwarding: {relay.circuit_forwarding} \n")
        
    print(f"{op.relay.name} \n all_circuits: {op.relay.all_circuits} \n circuit_forwarding: {op.relay.circuit_forwarding} \n")
    print(f"op circuits: {circuit} \n")

    
    # for relay in onion_relays:
    #     with relay.connections_lock:
    #         for connection in relay.connections:
    #             try:
    #                 connection.close()
    #             except Exception as e:
    #                 print(f"Error closing connection: {e}")
    #     try:
    #         relay.shutdown()
    #     except Exception as e:
    #         print(f"Error shutting down relay: {e}")
    
    # with op.relay.connections_lock:
    #     for connection in op.relay.connections:
    #         connection.close()
    # op.relay.shutdown()

    # Ensure all threads are joined
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()

    print("All threads joined. Exiting.")
    process.terminate()
    print("Flask server terminated.")
    process.wait()
    print("Flask server process exited.")


    
    
    
    