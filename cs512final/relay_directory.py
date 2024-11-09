# the code for the database holding the relays and their symmetric keys

class CircuitNode:
    def __init__(self, node_ip, node_key):
        self.node_ip = node_ip
        self.node_key = node_key
        
    
def fetch_circuit(src_ip, dest_ip):
    first_node = CircuitNode(src_ip, 'c944f98a31b0bee8501abf9fba108846')
    last_node = CircuitNode(dest_ip, 'a2aa66600e30db41609681c5a13f0075')
    return [first_node, last_node]