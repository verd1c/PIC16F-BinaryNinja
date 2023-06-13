from binaryninja import (
    InstructionTextToken,
    BranchType
)

class PIC16FDisassembler():
    
    def __init__(self):
        self.instructions = {
            0: ["hmm"]
        }