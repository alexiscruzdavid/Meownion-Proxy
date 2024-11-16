

NUMER_OF_RELAYS = 5
MAX_RELAYS = 30
MAX_CLIENTS = 30
dummy_ips = ['192.168.1.{}'.format(i) for i in range(0, NUMER_OF_RELAYS)]
dummy_port = 8443

# def create_dummy_relays():
#     for i in range(NUMER_OF_RELAYS):
#         relay = OnionRelay(dummy_ips[i], dummy_port, os.urandom(32))

