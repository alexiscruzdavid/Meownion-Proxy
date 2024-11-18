
import struct

CMD_ENUM = {
    'CREATE': 0,
    'EXTEND': 1,
    'DESTROY': 2,
    'RELAY': 3,
}

RELAY_CMD_ENUM = {
    'RELAY_DATA': 0,
    'EXTEND': 1,
    'DESTROY': 2,
}

class DefaultTorHeaderWrapper():

    def __init__(self):
        self.circID = None
        self.cmd = None
        self.data_len = None
        self.data = None
    
    def __init__(self, circID: int, cmd: str, data_len: int, data: bytearray):
        self.circID = circID
        self.cmd = CMD_ENUM[cmd]
        self.data_len = data_len
        self.data = data
    
    # constructs a message as a bytearray
    def createMessage(self):
        message = bytearray()
        packed_circid = struct.pack('<H', self.circID)
        packed_cmd = struct.pack('<B', self.cmd)
        packed_data_len = struct.pack('<H', self.data_len)
        
        message.append(packed_circid)
        message.append(packed_cmd)
        message.append(packed_data_len)
        message.extend(self.data)
        return message
    
    def unpackMessage(self, data: bytearray):
        self.circID = struct.unpack('<H', data[:2])
        self.cmd = struct.unpack('<B', data[2:3])
        self.data_len = struct.unpack('<H', data[3:5])
        self.data = data[5:]        
        
        
        
    
class RelayTorHeaderWrapper():
    def __init__(self):
        self.circID = None
        self.relay = None
        self.streamID = None
        self.digest = None
        self.data_len = None
        self.cmd = None
        self.data = None

    
    def __init__(self, circID: int, relay: str, streamID: int, digest: int, data_len: int, cmd: str, data: bytearray):
        self.circID = circID
        self.relay = relay
        self.streamID = streamID
        self.digest = digest
        self.data_len = len
        self.cmd = cmd
        self.data = data

    def createMessage(self):
        message = bytearray()
        packed_circID = struct.pack('<H', self.circID)
        packed_relay = struct.pack('<B', self.relay)
        packed_streamID = struct.pack('<H', self.streamID)
        # digest will be 8 bytes in our implementation due to python lack of unpacking 6 byte numbers
        packed_digest = struct.pack('<Q', self.digest)
        packed_data_len = struct.pack('<H', self.data_len)
        packed_cmd = struct.pack('<B', self.cmd)
    
        
        message.append(packed_circID)
        message.append(packed_cmd)
        message.append(packed_relay)
        message.append(packed_streamID)
        message.append(packed_digest)
        message.append(packed_data_len)
        message.append(packed_cmd)
        message.extend(self.data)
        return message

    def unpackMessage(self, data: bytearray):
        self.circID = struct.unpack('<H', data[:2])
        self.relay = struct.unpack('<B', data[2:3])
        self.streamID = struct.unpack('<H', data[3:5])
        # digest will be 8 bytes in our implementation due to python lack of unpacking 6 byte numbers
        self.digest = struct.unpack('<Q', data[5:13])
        self.data_len = struct.unpack('<H', data[13:15])
        self.cmd = struct.unpack('<B', data[15:16])
        self.data = data[18:]
    
    
