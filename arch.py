from binaryninja import (
    Architecture,
    Endianess,
    RegisterInfo,
    IntrinsicInfo,
    Type,
    InstructionInfo
)

class PIC16F(Architecture):
    name = "pic16f"
    
    endianess = Endianess.LittleEndian
    
    
    