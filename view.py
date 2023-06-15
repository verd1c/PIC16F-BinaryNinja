from binaryninja.enums import SectionSemantics
from struct import pack, iter_unpack
from .arch import PIC16Architecture
from binaryninja import (
    Architecture,
    BinaryReader,
    BinaryView,
    SegmentFlag,
)
from binaryninja.log import log_error
from .inhx32 import Record, RecordType

class IntelHexView(BinaryView):
    name = "INHX32"
    long_name = "Intel INHX32"
    start_address = 0
    
    def __init__(self, data):
        self.raw = data
        self.records = self.read_data_records(self.raw)
        # Swaps the order of the most-significant byte and the least-significant byte.
        # In Intel HEX, the LSB comes first and the MSB comes second, but those have to be swapped.
        # In addition to that, the 14 bit instructions are padded to 16 bit.
        self.binary_data = b''.join([pack('>H', z) for r in self.records for z, in iter_unpack('<H', r.data)])
        BinaryView.__init__(self, file_metadata=data.file, parent_view=BinaryView.new(data=self.binary_data))
        self.platform = Architecture[PIC16Architecture.name].standalone_platform

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
                    return bytes(line)
                if byte == ord('\n'):
                    yield bytes(line)
                    line = bytearray()
                else:
                    line.append(byte)
                offset += 1

        return [Record(line) for line in read_line()]

    def init(self):
        try:
            base_address = 0
            bytes_so_far = 0

            for record in self.records:
                if record.record_type == RecordType.Data: 
                    addr = base_address + record.address
                    flag = SegmentFlag.SegmentContainsData
                    self.add_auto_segment(addr, record.byte_count, bytes_so_far, record.byte_count, flag)
                elif record.record_type == RecordType.EndOfFile:
                    break
                elif record.record_type == RecordType.ExtendedLinearAddress:
                    base_address = int.from_bytes(record.data, byteorder='big') << 16
                elif record.record_type == RecordType.StartLinearAddress:
                    self.start_address = int.from_bytes(record.data, byteorder='big')
                    self.add_entry_point(self.start_address)
                bytes_so_far += record.byte_count
            self.add_auto_section("Program memory", 0, 0x7fff, semantics=SectionSemantics.ReadOnlyCodeSectionSemantics)
            self.add_auto_section("Configuration memory", 0x10000, 0x1fffe, semantics=SectionSemantics.ReadOnlyDataSectionSemantics)
            return True
        except:
            import traceback
            log_error(traceback.format_exc())
            return False

    def perform_get_address_size(self) -> int:
        # INHX32 supports up to 4GiB, or 32-bit, addresses
        return 32

    def perform_get_entry_point(self) -> int:
        return self.start_address

    def perform_is_executable(self) -> bool:
        return True
