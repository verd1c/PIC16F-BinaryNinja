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
        
    @classmethod
    def is_valid_for_data(cls, data):
        return True
    
    def init(self):
        self.platform = Architecture['pic16f'].standalone_platform
        self.arch = Architecture['pic16f']
        
        
        return True