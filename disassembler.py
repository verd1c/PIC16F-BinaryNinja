from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType
)

INSTR_TEXT_PADDING = 8

class PIC16FDisassembler():
    
    def __init__(self):
        
        # instruction lookup
        self.instruction_groups = {
            3: [{
                0x04: 'CALL',
                0x05: 'GOTO',
            }, self._disass_call_goto],
            4: [{
                0x04: 'BCF',
                0x05: 'BSF',
                0x06: 'BTFSC',
                0x07: 'BTFSS',
            }, self._disass_bit_filereg_op],
            5: [{
                0x19: 'BRA',
            }, self._disass_bra],
            6: {
                'BYTE_FILEREG_OP': [{
                    0x01: 'CLRF',
                    0x07: 'ADDWF',
                    0x3D: 'ADDWFC',
                    0x05: 'ANDWF',
                    0x37: 'ASRF',
                    0x35: 'LSLF',
                    0x36: 'LSRF',
                    0x09: 'COMF',
                    0x03: 'DECF',
                    0x0A: 'INCF',
                    0x04: 'IORWF',
                    0x08: 'MOVF',
                    0x0D: 'RLF',
                    0x0C: 'RRF',
                    0x02: 'SUBWF',
                    0x3B: 'SUBWFB',
                    0x0E: 'SWAPF',
                    0x06: 'XORWF',
                    0x0B: 'DECFSZ',
                    0x0F: 'INCFSZ',
                }, self._disass_byte_filereg_op],
                'LITERAL_GENERAL': [{
                    0x3E: 'ADDLW',
                    0x39: 'ANDLW',
                    0x38: 'IORLW',
                    0x30: 'MOVLW',
                    0x3C: 'SUBLW',
                    0x3A: 'XORLW',
                    0x34: 'RETLW',
                
                }, self._disass_literal_general],
            },
            # 7: [{
            #     0x01: 'MOVWF',
            #     0x63: 'MOVLP',
            #     0x62: 'ADDFSR',
            #     0x7E: 'MOVIW',
            #     0x7F: 'MOVWI',
            # }, self._disass_movlp_n_fsr_offset],
            7: {
                'MOVLP': [{
                    0x63: 'MOVLP',
                }, self._disass_movlp],
                'FSR_OFFSET': [{
                    0x01: 'MOVWF',
                    0x62: 'ADDFSR',
                    0x7E: 'MOVIW',
                    0x7F: 'MOVWI',
                }, self._disass_fsr_offset],
            },
            9: [{
                0x01: 'MOVLB',
            }, self._disass_movlb],
            11: [{
                0x0C: 'TRIS',
                0x02: 'MOVIW',
                0x03: 'MOVWI',
            }, self._disass_fsr_inc],
            12: [{
                0x40: 'CLRW',
            }, self._disass_clrw],
            14: [{
                0x00: 'NOP',
                0x01: 'RESET',
                0x08: 'RETURN',
                0x09: 'RETFIE',
                0x0A: 'CALLW',
                0x0B: 'BRW',
                0x62: 'OPTION',
                0x63: 'SLEEP',
                0x64: 'CLRWDT',
            }, self._disass_opcode_only],
            
        }
        
        return
    
    def disassemble(self, data: bytes, addr: int):
        
        if len(data) < 2:
            return
        
        instr = int.from_bytes(data[:2], 'big')
        
        for opcode_len, group_data in self.instruction_groups.items():
            
            groups_to_check = []
            if type(group_data) == dict:
                groups_to_check += [g for mn, g in group_data.items()]
            else:
                groups_to_check += [group_data]
                
            for group in groups_to_check:
                instrs = group[0]
                handler = group[1]
                masked_instr = instr >> (14 - opcode_len)
                
                if masked_instr in instrs.keys():
                    mnemonic = instrs[masked_instr]
                    return handler(mnemonic, instr, addr)
                
        print(f'Failed parsing instruction {bin(instr)} @ {hex(addr)}')
        return
    
    def _disass_call_goto(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        k = data & 0b11111111111
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(k), k))
        
        return tokens
    
    def _disass_bit_filereg_op(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        b = (data >> 7) & 0b111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{b:02x}  ", b))
        
        f = data & 0b1111111 
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{f:02x}  ", f))
        
        return tokens
    
    def _disass_bra(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        return tokens
    
    def _disass_literal_general(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        k = data & 0b11111111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{k:02x}", k))

        return tokens
    
    def _disass_byte_filereg_op(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        d = (data >> 7) & 1
        if d == 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "W     "))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "f     "))
        
        f = data & 0b1111111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{f:02x}", f))
        
        # tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, "\tComment Test"))

        return tokens
    
    def _disass_movlp(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        imm = data & 0b1111111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{imm:02x}", imm))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tPCLATH = 0x{imm:02x}"))
        
        return tokens
    
    def _disass_fsr_offset(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        n = (data >> 6) & 1
        if n == 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "FSR   "))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "INDF  "))
        
        k = data & 0b111111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{k:02x}", k))
        
        return tokens
    
    def _disass_movlb(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        bank = data & 0b11111
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{bank:02x}", bank))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tselect bank {bank}"))
        
        return tokens
    
    def _disass_fsr_inc(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        
        n = int(data[-3], 2)
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(n), n))
        
        m = int(data[-2:], 2)
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(m), m))
        
        return tokens
    
    # opcode only, just one token
    def _disass_opcode_only(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        return tokens
    
    def _disass_clrw(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic.ljust(INSTR_TEXT_PADDING, " "))]
        return tokens
    