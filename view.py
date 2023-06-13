from binaryninja import (
    Architecture,
    BinaryView,
    Endianness
)

class PIC16FLoader(BinaryView):
    name = "pic16f"
    long_name = "pic16f"
    
    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data