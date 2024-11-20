import socket
import relay_directory
import ssl
import sys
from tor_encryption import encrypt_message_with_circuit
from onion_relay import OnionRelay
from tor_header import DefaultTorHeaderWrapper, RelayTorHeaderWrapper
from tor_encryption import decrypt_message


def sender(src_ip, certfile, keyfile):    
    while True:
        message = input('Type in your message ')
        dest_ip = input('Type in your destination ip ')
        print('Sending Message {} to {}'.format(message, dest_ip))
        circuit = relay_directory.fetch_circuit(src_ip, dest_ip)

        cipher_text = encrypt_message_with_circuit(message.encode('utf-8'), circuit, 1, 1)


        current_relay = OnionRelay(name=src_ip, ip=src_ip, port=circuit[0].node_port, key=circuit[0].node_key)
        current_relay.start()
        
        # next_relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # next_relay_address = (circuit[1].node_ip, RELAY_SERVER_PORT)
    
        current_relay.relay_message_to_next(circuit[1].node_ip, circuit[1].node_port, cipher_text)
    

if __name__ == '__main__':
    print('Starting MeOwnion Proxy...')
    print(" /\_/\   ")
    print("( o.o )  ")
    print(" > ^ <   ")
    
    # hard coding inputs for testing purposes
    src_ip, certfile, keyfile = '152.3.53.250', 'certs/ca_cert.pem', 'certs/ca_key.key'
    
    # if len(sys.argv) > 2:
    #     src_ip, certfile, keyfile = sys.argv[1:]
    # elif len(sys.argv) > 1:
    #     src_ip = sys.argv[1]
    #     certfile = 'relay_cert.pem'
    #     keyfile = 'relay_key.pem'
    # else:
    #     print('Help Description: Create an onion proxy')
    #     print('format: python3 onion_proxy src_ip certfile keyfile')
    #     exit(1)

    print('The chosen onion proxy ip is {}'.format(src_ip))
    sender(src_ip, certfile, keyfile)
    

