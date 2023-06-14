from binaryninja import (
    Architecture,
    RegisterInfo,
    IntrinsicInfo,
    Type,
    InstructionInfo
)

class PIC16FArchitecture(Architecture):
    name = "pic16f"
    
    
    def __init__(self):
        super().__init__()
        
    
    
    