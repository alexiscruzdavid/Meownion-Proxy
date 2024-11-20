# the code for the database holding the relays and their symmetric keys

import os



class CircuitNode:
    def __init__(self, node_ip, node_port, node_key):
        self.node_ip = node_ip
        self.node_port = node_port
        self.node_key = node_key
        
# retrieve a circuit list comprised of CircuitNodes
def fetch_circuit(src_ip, dest_ip):
    first_node = CircuitNode(src_ip, 41200, b'\xf2\xc66\xcb\xb9\x05\xado\x9a\x96\xfcZRG\xe2\xaf\xcb\xc3\xf2"\xa7V\xe0sp\xf3h\xe1\x95I\x88Y')
    last_node = CircuitNode(dest_ip, 31200, b'\x7f\n<pP\xcf\x1f\x80\xd1\x1f\xe8K+"5\xe3\xb8\x92\x1f^\x12\xcc\xa1\x86\xba\xfa\xde\x1f%\x97.\xda')
    return [first_node, last_node]

def send_states():
    pass