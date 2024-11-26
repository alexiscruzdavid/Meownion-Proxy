import logging
import struct

RELAY_CMD_ENUM = {
    'RELAY_DATA': 0,
    'EXTEND': 1,
    'CREATE': 2,
}    

DATA_SIZE = 264
NULL_PORT = 65535

        
    
class RelayTorHeader():
    def __init__(self):
        self.circID = None
        self.cmd = None
        self.src_server_port = None
        self.dst_server_port = None
        self.data = None
        logging.basicConfig(level=logging.INFO)

    def initialize(self, circID: int, cmd: str, src_server_port: int, dst_server_port: int, data: bytearray):
        self.circID = circID
        self.cmd = RELAY_CMD_ENUM[cmd]
        self.src_server_port = src_server_port
        self.dst_server_port = dst_server_port
        self.data = data[:DATA_SIZE].ljust(DATA_SIZE, b'\x00') # Untested, from GPT

    def create_message(self):
        message = bytearray()
        packed_circID = struct.pack('H', self.circID)
        packed_cmd = struct.pack('H', self.cmd)
        packed_src_server_port = struct.pack('H', self.src_server_port)
        packed_dst_server_port = struct.pack('H', self.dst_server_port)
        
        message += packed_circID
        message += packed_cmd
        message += packed_src_server_port
        message += packed_dst_server_port
        message += self.data
        return (message[:6], message[6:])
    
    def unpack_message(self, data: bytearray):
        self.circID = struct.unpack('H', data[:2])[0]
        self.cmd = struct.unpack('H', data[2:4])[0]
        self.src_server_port = struct.unpack('H', data[4:6])[0]
        self.dst_server_port = struct.unpack('H', data[6:8])[0]
        self.data = data[8:]
    
    