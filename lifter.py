from binaryninja import (
    LowLevelILLabel,
    LowLevelILFunction,
)

from .instruction import *

class PIC16FLifter():
    
    def __init__(self):
        
        return
    
    def lift(self, data: bytes, addr: int, il: LowLevelILFunction):
        
        # check for MOVLPX CALL MOVLPX
        if len(data) >= 6:
            if (type(Instruction.new(data[0:2], addr)) == MovlpInstruction and
                Instruction.new(data[2:4], addr + 2).name == "GOTO" and
                type(Instruction.new(data[4:6], addr + 4)) == MovlpInstruction):
                
                # this should be aggregated
                print(f"call_far @ {hex(addr)}")
                
        if len(data) >= 6:
            cnd = Instruction.new(data[0:2], addr)
            if (cnd.name == "BTFSS" or cnd.name == "BTFSC"):
                
                # this should be aggregated
                print(f"conditional jump @ {hex(addr)}")
                # return Instruction.lift_conditional_jump(data[:6], addr, il)
                
        
        return Instruction.new(data, addr).lift(data, il)
