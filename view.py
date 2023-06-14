from binaryninja.enums import ModificationStatus
from .arch import PIC16Architecture
from binaryninja import (
    Architecture,
    BinaryReader,
    BinaryView,
    SegmentFlag,
)
from binaryninja.log import log_error, log_info
from .inhx32 import Record, RecordType

class IntelHexView(BinaryView):
    name = "INHX32"
    long_name = "Intel INHX32"
    start_address = 0
    
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
            line_start = 0
            while True:
                byte = br.read8(offset)
                if byte is None:
                    return line_start, bytes(line)
                if byte == ord('\n'):
                    yield line_start, bytes(line)
                    line = bytearray()
                    line_start = offset + 1
                else:
                    line.append(byte)
                offset += 1

        return [Record(line_start, line) for line_start, line in read_line()]

    def init(self):
        try:
            self.records = self.read_data_records(self.raw)
            base_address = 0
            for record in self.records:
                if record.record_type == RecordType.Data: 
                    addr = base_address + record.address
                    flag = SegmentFlag.SegmentContainsCode | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable
                    if base_address > 0:
                        flag = SegmentFlag.SegmentContainsData | SegmentFlag.SegmentReadable
                    self.add_auto_segment(addr, record.byte_count*2, record.file_offset+9, record.byte_count*2, flag)
                elif record.record_type == RecordType.EndOfFile:
                    break
                elif record.record_type == RecordType.ExtendedLinearAddress:
                    base_address = int.from_bytes(record.data, byteorder='big') << 16
                elif record.record_type == RecordType.StartLinearAddress:
                    self.start_address = int.from_bytes(record.data, byteorder='big')
                    self.add_entry_point(self.start_address)
            self.add_auto_section("Program memory", 0, 0x1fff)
            self.add_auto_section("Configuration memory", 0x8000, 0x200)
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
