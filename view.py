from .arch import PIC16Architecture
from binaryninja import (
    Architecture,
    BinaryReader,
    BinaryView,
)
from binaryninja.log import log_error, log_info
from .inhx32 import Record

class IntelHexView(BinaryView):
    name = "INHX32"
    long_name = "Intel INHX32"
    
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.platform = Architecture[PIC16Architecture.name].standalone_platform
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        try:
            cls.read_data_records(data)
            return True
        except:
            return False

    @classmethod
    def read_data_records(cls, data):
        def read_line():
            br = BinaryReader(data)
            offset = 0
            line = bytearray()
            while True:
                byte = br.read8(offset)
                if byte is None:
                    return line
                if byte == ord('\n'):
                    yield bytes(line)
                    line = bytearray()
                else:
                    line.append(byte)
                offset += 1

        return [Record(line) for line in read_line()]

    def init(self):
        try:
            self.read_data_records(self.raw)
            return True
        except:
            import traceback
            log_error(traceback.format_exc())
            return False

    def perform_get_address_size(self) -> int:
        # INHX32 supports up to 4GiB, or 32-bit, addresses
        return 32

    def perform_get_entry_point(self) -> int:
        # Can be set with the 05 record type
        return 0

    def perform_is_executable(self) -> bool:
        return True
