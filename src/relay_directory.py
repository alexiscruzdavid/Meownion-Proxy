# the code for the database holding the relays and their symmetric keys

import os



class CircuitNode:
    def __init__(self, node_ip, node_key):
        self.node_ip = node_ip
        self.node_key = node_key
        
# retrieve a circuit list comprised of CircuitNodes
def fetch_circuit(src_ip, dest_ip):
    first_node = CircuitNode(src_ip, os.urandom(32))
    last_node = CircuitNode(dest_ip, os.urandom(32))
    return [first_node, last_node]

def send_states():
    pass