from enum import Enum
from binaryninja.log import log_info

class RecordType(Enum):
    Data = 0
    EndOfFile = 1
    # These two are only used in INHX16
    # Extended Segment Address = 2
    # Start Segment Address = 3
    ExtendedLinearAddress = 4
    StartLinearAddress = 5

class Record():
    def __init__(self, line: bytes):
        self.parse(line)
    
    def parse(self, line: bytes):
        # Ignore all character preceding the first ':'
        start_code_idx = line.find(b':')
        if start_code_idx == -1:
            raise ValueError("Line does not contain valid start code")
        line = line[start_code_idx:]
        self.byte_count = int(line[1:3], 16)
        self.address = int(line[3:7], 16)
        self.record_type = RecordType(int(line[7:9], 16))

        end_data = self.byte_count*2
        self.data = bytes(line[9:9+end_data])
        self.checksum = line[9+end_data:11+end_data]
